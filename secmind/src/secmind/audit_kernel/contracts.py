from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA256_PATTERN = r"^[a-f0-9]{64}$"


class AuditContract(BaseModel):
    """Strict, immutable value object used by the v0.7 audit hot path."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class ReviewVerdict(StrEnum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"


class FlowVerdict(StrEnum):
    CANDIDATE_POSITIVE = "candidate_positive"
    CANDIDATE_NEGATIVE = "candidate_negative"
    UNKNOWN = "unknown"


class FlowEdgeKind(StrEnum):
    ASSIGNMENT = "assignment"
    ARGUMENT = "argument"
    CALL = "call"
    CONCATENATION = "concatenation"
    RETURN = "return"
    SANITIZATION = "sanitization"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class GainAction(StrEnum):
    KEEP_BASELINE = "keep_baseline"
    ACCEPT_ENHANCEMENT = "accept_enhancement"
    ACCEPT_CORRECTION = "accept_correction"


def canonical_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(f"unsafe or non-canonical repository path: {value!r}")
    return path.as_posix()


def content_digest(value: BaseModel | dict[str, Any]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stable_unit_id(
    *,
    input_manifest_digest: str,
    primary_path: str,
    source_sha256: str,
    target_cwes: tuple[int, ...] | list[int] | set[int] | frozenset[int],
    profile_digest: str,
) -> str:
    path = canonical_path(primary_path)
    cwes = sorted(set(target_cwes))
    if not cwes or any(cwe <= 0 for cwe in cwes):
        raise ValueError("target_cwes must contain positive CWE identifiers")
    for digest in (input_manifest_digest, source_sha256, profile_digest):
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("unit identity requires lowercase SHA-256 digests")
    digest = content_digest(
        {
            "input_manifest_digest": input_manifest_digest,
            "primary_path": path,
            "source_sha256": source_sha256,
            "target_cwes": cwes,
            "profile_digest": profile_digest,
        }
    )
    return f"unit-{digest}"


def stable_scope_digest(
    *,
    primary_path: str,
    support_paths: tuple[str, ...] | list[str],
    target_cwes: tuple[int, ...] | list[int],
    profile_digest: str,
    authorized_scope: tuple[str, ...] | list[str] = (".",),
) -> str:
    return content_digest(
        {
            "primary_path": canonical_path(primary_path),
            "support_paths": sorted({canonical_path(path) for path in support_paths}),
            "target_cwes": sorted(set(target_cwes)),
            "profile_digest": profile_digest,
            "authorized_scope": sorted(set(authorized_scope)),
        }
    )


class AuditUnit(AuditContract):
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    run_id: str = Field(min_length=1, max_length=128)
    language: Literal["java"] = "java"
    input_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    profile_digest: str = Field(pattern=SHA256_PATTERN)
    primary_path: str = Field(min_length=1, max_length=1024)
    source_sha256: str = Field(pattern=SHA256_PATTERN)
    target_cwes: tuple[int, ...] = Field(min_length=1)
    support_paths: tuple[str, ...] = ()
    support_symbol_refs: tuple[str, ...] = ()
    authorized_scope: tuple[str, ...] = (".",)
    snapshot_id: str | None = Field(default=None, pattern=r"^snapshot-[a-f0-9]{64}$")
    scope_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("primary_path")
    @classmethod
    def validate_primary_path(cls, value: str) -> str:
        normalized = canonical_path(value)
        if normalized != value.replace("\\", "/"):
            raise ValueError("primary_path must already be canonical")
        return normalized

    @field_validator("support_paths")
    @classmethod
    def validate_support_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({canonical_path(value) for value in values}))

    @field_validator("support_symbol_refs")
    @classmethod
    def normalize_symbol_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value.strip() for value in values if value.strip()}))

    @field_validator("authorized_scope")
    @classmethod
    def normalize_authorized_scope(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({value.replace("\\", "/").rstrip("/") or "." for value in values}))
        if not normalized or any(
            value.startswith("/") or value.startswith("../") or "/../" in value for value in normalized
        ):
            raise ValueError("authorized_scope must contain safe relative paths")
        return normalized

    @field_validator("target_cwes")
    @classmethod
    def normalize_cwes(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        normalized = tuple(sorted(set(values)))
        if not normalized or any(value <= 0 for value in normalized):
            raise ValueError("target_cwes must contain positive CWE identifiers")
        return normalized

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        expected_unit_id = stable_unit_id(
            input_manifest_digest=self.input_manifest_digest,
            primary_path=self.primary_path,
            source_sha256=self.source_sha256,
            target_cwes=self.target_cwes,
            profile_digest=self.profile_digest,
        )
        if self.unit_id != expected_unit_id:
            raise ValueError("unit_id does not match immutable unit content")
        expected_scope = stable_scope_digest(
            primary_path=self.primary_path,
            support_paths=self.support_paths,
            target_cwes=self.target_cwes,
            profile_digest=self.profile_digest,
            authorized_scope=self.authorized_scope,
        )
        if self.scope_digest != expected_scope:
            raise ValueError("scope_digest does not match unit scope")
        return self

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        input_manifest_digest: str,
        profile_digest: str,
        primary_path: str,
        source_sha256: str,
        target_cwes: tuple[int, ...] | list[int] | set[int] | frozenset[int],
        support_paths: tuple[str, ...] | list[str] = (),
        support_symbol_refs: tuple[str, ...] | list[str] = (),
        authorized_scope: tuple[str, ...] | list[str] = (".",),
        snapshot_id: str | None = None,
    ) -> Self:
        path = canonical_path(primary_path)
        cwes = tuple(sorted(set(target_cwes)))
        normalized_support = tuple(sorted({canonical_path(value) for value in support_paths}))
        return cls(
            unit_id=stable_unit_id(
                input_manifest_digest=input_manifest_digest,
                primary_path=path,
                source_sha256=source_sha256,
                target_cwes=cwes,
                profile_digest=profile_digest,
            ),
            run_id=run_id,
            input_manifest_digest=input_manifest_digest,
            profile_digest=profile_digest,
            primary_path=path,
            source_sha256=source_sha256,
            target_cwes=cwes,
            support_paths=normalized_support,
            support_symbol_refs=tuple(support_symbol_refs),
            authorized_scope=tuple(authorized_scope),
            snapshot_id=snapshot_id,
            scope_digest=stable_scope_digest(
                primary_path=path,
                support_paths=normalized_support,
                target_cwes=cwes,
                profile_digest=profile_digest,
                authorized_scope=tuple(authorized_scope),
            ),
        )


class CodeSite(AuditContract):
    node_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    line: int = Field(ge=1)
    column: int = Field(default=1, ge=1)
    family: str = Field(min_length=1, max_length=128)
    symbol: str | None = Field(default=None, max_length=256)
    file_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return canonical_path(value)


class FlowEdge(AuditContract):
    edge_id: str = Field(min_length=1, max_length=128)
    from_node_id: str = Field(min_length=1, max_length=128)
    to_node_id: str = Field(min_length=1, max_length=128)
    kind: FlowEdgeKind = FlowEdgeKind.UNKNOWN
    symbol: str | None = Field(default=None, max_length=256)


def _flow_payload(
    *,
    unit_id: str,
    cwe: int,
    source_site: CodeSite | None,
    sink_site: CodeSite,
    propagation_edges: tuple[FlowEdge, ...],
    sanitizer_sites: tuple[CodeSite, ...],
    branch_conditions: tuple[str, ...],
    tool_name: str,
    tool_version: str,
    rule_bundle_digest: str,
    verdict: FlowVerdict,
) -> dict[str, Any]:
    return {
        "unit_id": unit_id,
        "cwe": cwe,
        "source_site": None if source_site is None else source_site.model_dump(mode="json"),
        "sink_site": sink_site.model_dump(mode="json"),
        "propagation_edges": [edge.model_dump(mode="json") for edge in propagation_edges],
        "sanitizer_sites": [site.model_dump(mode="json") for site in sanitizer_sites],
        "branch_conditions": list(branch_conditions),
        "tool_name": tool_name,
        "tool_version": tool_version,
        "rule_bundle_digest": rule_bundle_digest,
        "verdict": verdict.value,
    }


class CandidateFlow(AuditContract):
    flow_id: str = Field(pattern=r"^flow-[a-f0-9]{64}$")
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    cwe: int = Field(gt=0)
    source_site: CodeSite | None = None
    sink_site: CodeSite
    propagation_edges: tuple[FlowEdge, ...] = ()
    sanitizer_sites: tuple[CodeSite, ...] = ()
    branch_conditions: tuple[str, ...] = ()
    tool_name: str = Field(min_length=1, max_length=128)
    tool_version: str = Field(min_length=1, max_length=128)
    rule_bundle_digest: str = Field(pattern=SHA256_PATTERN)
    verdict: FlowVerdict
    confidence: float = Field(ge=0, le=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("evidence_ids")
    @classmethod
    def normalize_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    @model_validator(mode="after")
    def validate_flow_id(self) -> Self:
        expected = "flow-" + content_digest(
            _flow_payload(
                unit_id=self.unit_id,
                cwe=self.cwe,
                source_site=self.source_site,
                sink_site=self.sink_site,
                propagation_edges=self.propagation_edges,
                sanitizer_sites=self.sanitizer_sites,
                branch_conditions=self.branch_conditions,
                tool_name=self.tool_name,
                tool_version=self.tool_version,
                rule_bundle_digest=self.rule_bundle_digest,
                verdict=self.verdict,
            )
        )
        if self.flow_id != expected:
            raise ValueError("flow_id does not match candidate flow content")
        return self

    @property
    def lineage_id(self) -> str:
        return f"tool:{self.tool_name}:{self.tool_version}:{self.rule_bundle_digest}"

    @classmethod
    def create(
        cls,
        *,
        unit_id: str,
        cwe: int,
        source_site: CodeSite | None,
        sink_site: CodeSite,
        propagation_edges: tuple[FlowEdge, ...] | list[FlowEdge],
        sanitizer_sites: tuple[CodeSite, ...] | list[CodeSite] = (),
        branch_conditions: tuple[str, ...] | list[str] = (),
        tool_name: str,
        tool_version: str,
        rule_bundle_digest: str,
        verdict: FlowVerdict,
        confidence: float,
        evidence_ids: tuple[str, ...] | list[str],
    ) -> Self:
        edges = tuple(propagation_edges)
        sanitizers = tuple(sanitizer_sites)
        conditions = tuple(branch_conditions)
        payload = _flow_payload(
            unit_id=unit_id,
            cwe=cwe,
            source_site=source_site,
            sink_site=sink_site,
            propagation_edges=edges,
            sanitizer_sites=sanitizers,
            branch_conditions=conditions,
            tool_name=tool_name,
            tool_version=tool_version,
            rule_bundle_digest=rule_bundle_digest,
            verdict=verdict,
        )
        return cls(
            flow_id="flow-" + content_digest(payload),
            unit_id=unit_id,
            cwe=cwe,
            source_site=source_site,
            sink_site=sink_site,
            propagation_edges=edges,
            sanitizer_sites=sanitizers,
            branch_conditions=conditions,
            tool_name=tool_name,
            tool_version=tool_version,
            rule_bundle_digest=rule_bundle_digest,
            verdict=verdict,
            confidence=confidence,
            evidence_ids=tuple(evidence_ids),
        )


class PrimaryVerdict(AuditContract):
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    verdict: ReviewVerdict
    cwe: int | None = Field(default=None, gt=0)
    # The line is a model judgment validated against the immutable source by
    # the host. Keeping it in the verdict makes a recovered positive usable
    # without replaying a paid provider call or guessing a locator later.
    sink_line: int | None = Field(default=None, ge=1)
    source_node_id: str | None = Field(default=None, max_length=128)
    sink_node_id: str | None = Field(default=None, max_length=128)
    confidence: float = Field(ge=0, le=1)
    reason_codes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    receipt_id: str = Field(min_length=1, max_length=256)
    model_id: str | None = Field(default=None, min_length=1, max_length=256)
    prompt_version: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_ids: tuple[str, ...] = ()

    @field_validator("evidence_ids", "reason_codes", "limitations")
    @classmethod
    def normalize_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    @model_validator(mode="after")
    def require_positive_path(self) -> Self:
        if self.verdict == ReviewVerdict.VULNERABLE and (
            self.cwe is None or self.source_node_id is None or self.sink_node_id is None
        ):
            raise ValueError("positive primary verdicts require CWE, source node and sink node")
        return self


class CriticVerdict(AuditContract):
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    verdict: ReviewVerdict
    cwe: int | None = Field(default=None, gt=0)
    source_node_id: str | None = Field(default=None, max_length=128)
    sink_node_id: str | None = Field(default=None, max_length=128)
    confidence: float = Field(ge=0, le=1)
    receipt_id: str = Field(min_length=1, max_length=256)
    lineage_id: str = Field(min_length=1, max_length=512)
    model_id: str | None = Field(default=None, min_length=1, max_length=256)
    prompt_version: str | None = Field(default=None, min_length=1, max_length=256)
    evidence_ids: tuple[str, ...] = ()

    @field_validator("evidence_ids")
    @classmethod
    def normalize_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    @model_validator(mode="after")
    def require_positive_path(self) -> Self:
        if self.verdict == ReviewVerdict.VULNERABLE and (
            self.cwe is None or self.source_node_id is None or self.sink_node_id is None
        ):
            raise ValueError("positive critic verdicts require CWE, source node and sink node")
        return self


class SemanticCheck(AuditContract):
    check_id: str = Field(min_length=1, max_length=128)
    passed: bool
    detail: str = Field(default="", max_length=512)


class StructuralConsistencyCertificate(AuditContract):
    """Parser-produced integrity proof, not an authoritative semantic judgment."""

    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    flow_id: str = Field(pattern=r"^flow-[a-f0-9]{64}$")
    valid: bool
    checks: tuple[SemanticCheck, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    certificate_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("evidence_ids")
    @classmethod
    def normalize_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    def digest_valid(self) -> bool:
        payload = self.model_dump(mode="json", exclude={"certificate_digest"})
        return self.certificate_digest == content_digest(payload)

    @classmethod
    def create(
        cls,
        *,
        unit_id: str,
        flow_id: str,
        checks: tuple[SemanticCheck, ...] | list[SemanticCheck],
        evidence_ids: tuple[str, ...] | list[str],
    ) -> Self:
        check_values = tuple(checks)
        draft = cls.model_construct(
            unit_id=unit_id,
            flow_id=flow_id,
            valid=bool(check_values) and all(check.passed for check in check_values),
            checks=check_values,
            evidence_ids=tuple(sorted(set(evidence_ids))),
            certificate_digest="0" * 64,
        )
        return cls.model_validate(
            {
                **draft.model_dump(mode="json"),
                "certificate_digest": content_digest(draft.model_dump(mode="json", exclude={"certificate_digest"})),
            }
        )


# Compatibility name for persisted v0.7 callers. New production code uses the
# precise structural name and never treats this object as semantic authority.
SemanticCertificate = StructuralConsistencyCertificate


class GainPolicy(AuditContract):
    policy_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    approved_tool_names: tuple[str, ...] = Field(min_length=1)
    approved_rule_bundle_digests: tuple[str, ...] = Field(min_length=1)
    allowed_cwes: tuple[int, ...] = ()
    minimum_tool_confidence: float = Field(default=0.85, ge=0, le=1)
    minimum_critic_confidence: float = Field(default=0.85, ge=0, le=1)
    minimum_correction_tool_confidence: float = Field(default=0.8, ge=0, le=1)
    minimum_correction_critic_confidence: float = Field(default=0.9, ge=0, le=1)
    policy_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @field_validator("approved_tool_names")
    @classmethod
    def normalize_tool_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    @field_validator("approved_rule_bundle_digests")
    @classmethod
    def normalize_rule_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))

    @field_validator("allowed_cwes")
    @classmethod
    def normalize_allowed_cwes(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted({value for value in values if value > 0}))

    def digest_valid(self) -> bool:
        if self.policy_digest is None:
            return False
        return self.policy_digest == content_digest(self.model_dump(mode="json", exclude={"policy_digest"}))

    @classmethod
    def create(cls, **values: Any) -> Self:
        draft = cls.model_validate({**values, "policy_digest": None})
        return cls.model_validate(
            {
                **draft.model_dump(mode="json"),
                "policy_digest": content_digest(draft.model_dump(mode="json", exclude={"policy_digest"})),
            }
        )


class UnitDecision(AuditContract):
    unit_id: str = Field(pattern=r"^unit-[a-f0-9]{64}$")
    action: GainAction
    baseline_verdict: ReviewVerdict
    final_verdict: ReviewVerdict
    baseline_cwe: int | None = Field(default=None, gt=0)
    final_cwe: int | None = Field(default=None, gt=0)
    baseline_receipt_id: str = Field(min_length=1, max_length=256)
    accepted_flow_id: str | None = Field(default=None, pattern=r"^flow-[a-f0-9]{64}$")
    patch_release_id: str | None = Field(default=None, pattern=r"^patch-release-[a-f0-9]{64}$")
    critic_receipt_id: str | None = Field(default=None, max_length=256)
    semantic_certificate_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    policy_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    evidence_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = Field(min_length=1)
    decision_digest: str = Field(pattern=SHA256_PATTERN)

    @field_validator("evidence_ids", "reason_codes")
    @classmethod
    def normalize_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value for value in values if value}))

    def digest_valid(self) -> bool:
        return self.decision_digest == content_digest(self.model_dump(mode="json", exclude={"decision_digest"}))

    @classmethod
    def create(cls, **values: Any) -> Self:
        draft = cls.model_validate({**values, "decision_digest": "0" * 64})
        return cls.model_validate(
            {
                **draft.model_dump(mode="json"),
                "decision_digest": content_digest(draft.model_dump(mode="json", exclude={"decision_digest"})),
            }
        )
