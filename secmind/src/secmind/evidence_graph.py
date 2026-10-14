from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from secmind.outcomes import stable_digest
from secmind.schemas import (
    SCHEMA_VERSION,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
    Finding,
    VerificationResult,
)


class EvidenceGraphError(ValueError):
    """The evidence graph contains an invalid reference or state transition."""


EVIDENCE_STATUS_AVAILABLE = "available"
EVIDENCE_STATUS_INVALID = "invalid"
EVIDENCE_STATUS_STALE = "stale"
EVIDENCE_STATUS_UNAVAILABLE = "unavailable"
EVIDENCE_STATUSES = frozenset(
    {
        EVIDENCE_STATUS_AVAILABLE,
        EVIDENCE_STATUS_INVALID,
        EVIDENCE_STATUS_STALE,
        EVIDENCE_STATUS_UNAVAILABLE,
    }
)
EVIDENCE_ROLE_REQUIRED_SUPPORT = "required_support"
EVIDENCE_ROLE_SUPPLEMENTAL = "supplemental"
EVIDENCE_ROLE_CONTRADICTORY = "contradictory"
EVIDENCE_ROLES = frozenset(
    {
        EVIDENCE_ROLE_REQUIRED_SUPPORT,
        EVIDENCE_ROLE_SUPPLEMENTAL,
        EVIDENCE_ROLE_CONTRADICTORY,
    }
)
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class EvidenceValidation:
    """The graph's deterministic publishability decision for one evidence item."""

    evidence_id: str
    status: str = EVIDENCE_STATUS_AVAILABLE
    reason: str | None = None

    @property
    def publishable(self) -> bool:
        return self.status == EVIDENCE_STATUS_AVAILABLE


ALLOWED_TRANSITIONS: dict[ClaimStatus, frozenset[ClaimStatus]] = {
    ClaimStatus.CANDIDATE: frozenset(
        {
            ClaimStatus.SUPPORTED,
            ClaimStatus.REJECTED,
            ClaimStatus.CONFLICTED,
            ClaimStatus.INSUFFICIENT,
        }
    ),
    ClaimStatus.SUPPORTED: frozenset(
        {
            ClaimStatus.VERIFIED,
            ClaimStatus.REJECTED,
            ClaimStatus.CONFLICTED,
            ClaimStatus.INSUFFICIENT,
        }
    ),
    ClaimStatus.VERIFIED: frozenset(),
    ClaimStatus.REJECTED: frozenset(),
    ClaimStatus.CONFLICTED: frozenset(),
    ClaimStatus.INSUFFICIENT: frozenset(),
}


def stable_claim_id(
    *,
    claim_type: str,
    statement: str,
    subject_ref: str,
    producer: str,
    version: str,
) -> str:
    digest = stable_digest(
        {
            "claim_type": claim_type,
            "statement": statement,
            "subject_ref": subject_ref,
            "producer": producer,
            "version": version,
        }
    )
    return str(uuid5(NAMESPACE_URL, f"secmind:claim:{digest}"))


def stable_link_id(
    *,
    claim_id: str,
    evidence_id: str,
    relation: EvidenceRelation,
    grader_id: str | None,
) -> str:
    digest = stable_digest(
        {
            "claim_id": claim_id,
            "evidence_id": evidence_id,
            "relation": relation.value,
            "grader_id": grader_id,
        }
    )
    return str(uuid5(NAMESPACE_URL, f"secmind:evidence-link:{digest}"))


def make_claim(
    *,
    claim_type: str,
    statement: str,
    subject_ref: str,
    producer: str,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN",
    confidence: float = 0,
    version: str = SCHEMA_VERSION,
) -> Claim:
    return Claim(
        claim_id=stable_claim_id(
            claim_type=claim_type,
            statement=statement,
            subject_ref=subject_ref,
            producer=producer,
            version=version,
        ),
        claim_type=claim_type,
        statement=statement,
        subject_ref=subject_ref,
        producer=producer,
        severity=severity,
        confidence=confidence,
        version=version,
    )


def make_link(
    *,
    claim_id: str,
    evidence_id: str,
    relation: EvidenceRelation = EvidenceRelation.SUPPORTS,
    weight: float = 1,
    grader_id: str | None = None,
) -> EvidenceLink:
    return EvidenceLink(
        link_id=stable_link_id(
            claim_id=claim_id,
            evidence_id=evidence_id,
            relation=relation,
            grader_id=grader_id,
        ),
        claim_id=claim_id,
        evidence_id=evidence_id,
        relation=relation,
        weight=weight,
        grader_id=grader_id,
    )


@dataclass(frozen=True)
class VerifiedReportProjection:
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    claim_ids: tuple[str, ...]
    excluded_finding_ids: tuple[str, ...]
    notes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def evidence_notes(self) -> Mapping[str, tuple[str, ...]]:
        """Backward/forward-friendly name for consumers rendering limitations."""

        return self.notes


class EvidenceGraph:
    """Deterministic graph with strict referential integrity and verifier-owned transitions."""

    def __init__(
        self,
        *,
        claims: Iterable[Claim] = (),
        evidence: Iterable[Evidence] = (),
        links: Iterable[EvidenceLink] = (),
        expected_input_manifest_digest: str | None = None,
        expected_file_sha256_by_path: Mapping[str, str] | None = None,
        expected_rule_bundle_digests: Mapping[str, str] | None = None,
    ) -> None:
        self._expected_input_manifest_digest = _validated_optional_digest(
            expected_input_manifest_digest,
            field_name="expected_input_manifest_digest",
        )
        self._expected_file_sha256_by_path = _normalize_expected_file_digests(expected_file_sha256_by_path)
        self._expected_rule_bundle_digests = _normalize_expected_rule_digests(expected_rule_bundle_digests)
        self._claims: dict[str, Claim] = {}
        self._evidence: dict[str, Evidence] = {}
        self._links: dict[str, EvidenceLink] = {}
        for evidence_item in evidence:
            self.add_evidence(evidence_item)
        for claim_item in claims:
            self.add_claim(claim_item)
        for link_item in links:
            self.add_link(link_item)

    @property
    def claims(self) -> tuple[Claim, ...]:
        return tuple(self._claims[key] for key in sorted(self._claims))

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return tuple(self._evidence[key] for key in sorted(self._evidence))

    @property
    def links(self) -> tuple[EvidenceLink, ...]:
        return tuple(self._links[key] for key in sorted(self._links))

    def add_claim(self, claim: Claim) -> None:
        existing = self._claims.get(claim.claim_id)
        if existing is not None and existing != claim:
            raise EvidenceGraphError(f"Claim id {claim.claim_id} was reused with different content")
        self._claims[claim.claim_id] = claim.model_copy(deep=True)

    def add_evidence(self, evidence: Evidence) -> None:
        existing = self._evidence.get(evidence.evidence_id)
        if existing is not None and existing != evidence:
            raise EvidenceGraphError(f"Evidence id {evidence.evidence_id} was reused with different content")
        self._evidence[evidence.evidence_id] = evidence.model_copy(deep=True)

    def validate_evidence(self, evidence_id: str) -> EvidenceValidation:
        """Validate status and immutable scanner bindings without reading source bytes."""

        try:
            evidence = self._evidence[evidence_id]
        except KeyError as exc:
            raise EvidenceGraphError(f"Unknown evidence {evidence_id}") from exc
        return _validate_evidence(
            evidence,
            expected_input_manifest_digest=self._expected_input_manifest_digest,
            expected_file_sha256_by_path=self._expected_file_sha256_by_path,
            expected_rule_bundle_digests=self._expected_rule_bundle_digests,
        )

    def evidence_status(self, evidence_id: str) -> str:
        return self.validate_evidence(evidence_id).status

    def evidence_is_publishable(self, evidence_id: str) -> bool:
        return self.validate_evidence(evidence_id).publishable

    def add_link(self, link: EvidenceLink) -> None:
        if link.claim_id not in self._claims:
            raise EvidenceGraphError(f"Evidence link references unknown claim {link.claim_id}")
        if link.evidence_id not in self._evidence:
            raise EvidenceGraphError(f"Evidence link references unknown evidence {link.evidence_id}")
        existing = self._links.get(link.link_id)
        if existing is not None and existing != link:
            raise EvidenceGraphError(f"Evidence link id {link.link_id} was reused with different content")
        self._links[link.link_id] = link.model_copy(deep=True)

    def claim(self, claim_id: str) -> Claim:
        try:
            return self._claims[claim_id].model_copy(deep=True)
        except KeyError as exc:
            raise EvidenceGraphError(f"Unknown claim {claim_id}") from exc

    def evidence_for_claim(self, claim_id: str) -> tuple[Evidence, ...]:
        self.claim(claim_id)
        identifiers = {link.evidence_id for link in self._links.values() if link.claim_id == claim_id}
        return tuple(self._evidence[key].model_copy(deep=True) for key in sorted(identifiers))

    def links_for_claim(self, claim_id: str) -> tuple[EvidenceLink, ...]:
        self.claim(claim_id)
        return tuple(
            link.model_copy(deep=True)
            for link in sorted(self._links.values(), key=lambda item: item.link_id)
            if link.claim_id == claim_id
        )

    def apply_verification(self, result: VerificationResult) -> None:
        current = self.claim(result.claim_id)
        target = result.status
        if target == current.status:
            return
        links = self.links_for_claim(current.claim_id)
        linked = {link.evidence_id for link in links}
        verified = set(result.verified_evidence_ids)
        rejected = set(result.rejected_evidence_ids)
        if not verified <= linked or not rejected <= linked:
            raise EvidenceGraphError("Verification result references evidence not linked to its claim")
        for evidence_id in sorted(verified):
            validation = self.validate_evidence(evidence_id)
            if not validation.publishable:
                raise EvidenceGraphError(
                    f"Evidence {evidence_id} is {validation.status} and cannot be verifier-approved"
                )
        if target == ClaimStatus.VERIFIED:
            verified_support = any(
                link.evidence_id in verified
                and link.relation == EvidenceRelation.SUPPORTS
                and self.evidence_is_publishable(link.evidence_id)
                for link in links
            )
            if not verified_support:
                raise EvidenceGraphError("A verified claim requires integrity-checked supporting evidence")
        if target == ClaimStatus.VERIFIED and current.status == ClaimStatus.CANDIDATE:
            current.status = ClaimStatus.SUPPORTED
            self._claims[current.claim_id] = current
        current = self.claim(result.claim_id)
        if target not in ALLOWED_TRANSITIONS[current.status]:
            raise EvidenceGraphError(
                f"Invalid claim transition {current.status.value} -> {target.value} for {current.claim_id}"
            )
        current.status = target
        current.confidence = result.confidence
        self._claims[current.claim_id] = current
        for link_id, link in tuple(self._links.items()):
            if link.claim_id != current.claim_id:
                continue
            if link.evidence_id in verified:
                link.verifier_status = ClaimStatus.VERIFIED
            elif link.evidence_id in rejected or target == ClaimStatus.REJECTED:
                link.verifier_status = ClaimStatus.REJECTED
            elif target in {ClaimStatus.CONFLICTED, ClaimStatus.INSUFFICIENT}:
                link.verifier_status = target
            self._links[link_id] = link

    def verified_report_projection(self, findings: Iterable[Finding]) -> VerifiedReportProjection:
        by_finding: dict[str, list[Claim]] = {}
        for claim in self._claims.values():
            by_finding.setdefault(claim.subject_ref, []).append(claim)
        included: list[Finding] = []
        excluded: list[str] = []
        claim_ids: set[str] = set()
        evidence_ids: set[str] = set()
        notes: dict[str, tuple[str, ...]] = {}

        # A clean audit still needs an observable proof of what ran. Coverage
        # claims are not Findings, so the finding-only projection below used to
        # erase their verifier-approved evidence from an otherwise COMPLETE
        # report. Include only coverage claims with an explicitly verified
        # supporting edge; candidate or merely linked evidence stays hidden.
        for claim in self._claims.values():
            if claim.status != ClaimStatus.VERIFIED or not claim.claim_type.endswith(".coverage"):
                continue
            supported = {
                link.evidence_id
                for link in self.links_for_claim(claim.claim_id)
                if link.relation == EvidenceRelation.SUPPORTS
                and link.verifier_status == ClaimStatus.VERIFIED
                and self.evidence_is_publishable(link.evidence_id)
            }
            if not supported:
                continue
            claim_ids.add(claim.claim_id)
            evidence_ids.update(supported)

        for finding in sorted(findings, key=lambda item: item.finding_id):
            finding_notes: list[str] = []
            verified = [
                claim for claim in by_finding.get(finding.finding_id, []) if claim.status == ClaimStatus.VERIFIED
            ]
            if not verified:
                notes[finding.finding_id] = ("claim_unverified",)
                excluded.append(finding.finding_id)
                continue
            supported = {
                link.evidence_id
                for claim in verified
                for link in self.links_for_claim(claim.claim_id)
                if link.relation == EvidenceRelation.SUPPORTS and link.verifier_status == ClaimStatus.VERIFIED
            }
            contradictory = {
                link.evidence_id
                for claim in verified
                for link in self.links_for_claim(claim.claim_id)
                if link.relation == EvidenceRelation.CONTRADICTS and link.verifier_status == ClaimStatus.VERIFIED
            }
            verified_link_ids = {
                link.evidence_id
                for claim in verified
                for link in self.links_for_claim(claim.claim_id)
                if link.verifier_status == ClaimStatus.VERIFIED
            }
            contradictory.update(
                evidence_id
                for evidence_id in verified_link_ids
                if evidence_id in self._evidence
                and evidence_role(self._evidence[evidence_id]) == EVIDENCE_ROLE_CONTRADICTORY
            )
            if contradictory:
                finding_notes.append("verified_contradictory_evidence")

            candidate_ids = set(finding.evidence_ids)
            if not candidate_ids:
                finding_notes.append("missing_evidence_reference")
                notes[finding.finding_id] = tuple(sorted(set(finding_notes)))
                excluded.append(finding.finding_id)
                continue
            unknown = candidate_ids - set(self._evidence)
            if unknown:
                finding_notes.extend(f"unknown_evidence:{item}" for item in sorted(unknown))
            for evidence_id in sorted(candidate_ids & set(self._evidence)):
                validation = self.validate_evidence(evidence_id)
                if not validation.publishable:
                    finding_notes.append(f"{validation.status}:{evidence_id}")
            publishable_supported = {
                evidence_id
                for evidence_id in supported & candidate_ids
                if evidence_id in self._evidence and self.evidence_is_publishable(evidence_id)
            }
            required_ids, required_field_present = _required_evidence_ids(finding)
            if not required_field_present:
                required_ids = {
                    evidence_id
                    for evidence_id in candidate_ids
                    if evidence_id in self._evidence
                    and evidence_role(self._evidence[evidence_id]) == EVIDENCE_ROLE_REQUIRED_SUPPORT
                }
            if required_ids - publishable_supported:
                finding_notes.append("required_support_missing")
            if not publishable_supported:
                finding_notes.append("verified_support_missing")
            supplemental = candidate_ids - publishable_supported
            for evidence_id in sorted(supplemental):
                if evidence_id in unknown or evidence_id not in self._evidence:
                    continue
                if evidence_id not in supported:
                    finding_notes.append(f"supplemental_unverified:{evidence_id}")

            if contradictory or unknown or required_ids - publishable_supported or not publishable_supported:
                notes[finding.finding_id] = tuple(sorted(set(finding_notes)))
                excluded.append(finding.finding_id)
                continue
            finding_copy = finding.model_copy(deep=True)
            if finding_notes:
                finding_copy.raw["evidence_limitations"] = sorted(set(finding_notes))
            included.append(finding_copy)
            if finding_notes:
                notes[finding.finding_id] = tuple(sorted(set(finding_notes)))
            claim_ids.update(claim.claim_id for claim in verified)
            evidence_ids.update(publishable_supported)
        return VerifiedReportProjection(
            findings=tuple(included),
            evidence=tuple(self._evidence[key].model_copy(deep=True) for key in sorted(evidence_ids)),
            claim_ids=tuple(sorted(claim_ids)),
            excluded_finding_ids=tuple(sorted(excluded)),
            notes=dict(sorted(notes.items())),
        )


def evidence_role(evidence: Evidence) -> str:
    """Return a compatibility-safe role from metadata, defaulting to supplemental."""

    raw = evidence.metadata.get("evidence_role", evidence.metadata.get("role"))
    if isinstance(raw, str):
        normalized = raw.strip().casefold().replace("-", "_").replace(" ", "_")
        if normalized in EVIDENCE_ROLES:
            return normalized
        if normalized in {"required", "support", "required_supporting"}:
            return EVIDENCE_ROLE_REQUIRED_SUPPORT
        if normalized in {"contradiction", "refutation"}:
            return EVIDENCE_ROLE_CONTRADICTORY
    if evidence.metadata.get("required_support") is True:
        return EVIDENCE_ROLE_REQUIRED_SUPPORT
    if evidence.metadata.get("contradictory") is True:
        return EVIDENCE_ROLE_CONTRADICTORY
    return EVIDENCE_ROLE_SUPPLEMENTAL


def _validated_optional_digest(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return value.lower()


def _normalize_expected_file_digests(values: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for path, digest in (values or {}).items():
        normalized_path = str(path).replace("\\", "/")
        if not normalized_path:
            raise ValueError("expected file digest path must not be empty")
        result[normalized_path.casefold()] = (
            _validated_optional_digest(
                digest,
                field_name=f"expected file digest for {path}",
            )
            or ""
        )
    return result


def _normalize_expected_rule_digests(values: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for tool, digest in (values or {}).items():
        result[str(tool).casefold()] = (
            _validated_optional_digest(
                digest,
                field_name=f"expected rule bundle digest for {tool}",
            )
            or ""
        )
    return result


def _metadata_digest(metadata: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            return ""
        return value.lower()
    return None


def _validate_evidence(
    evidence: Evidence,
    *,
    expected_input_manifest_digest: str | None,
    expected_file_sha256_by_path: Mapping[str, str],
    expected_rule_bundle_digests: Mapping[str, str],
) -> EvidenceValidation:
    metadata = evidence.metadata
    explicit_status = metadata.get("evidence_status", metadata.get("status", metadata.get("availability")))
    if metadata.get("stale") is True:
        return EvidenceValidation(evidence.evidence_id, EVIDENCE_STATUS_STALE, "evidence is explicitly marked stale")
    if metadata.get("invalid") is True:
        return EvidenceValidation(
            evidence.evidence_id,
            EVIDENCE_STATUS_INVALID,
            "evidence is explicitly marked invalid",
        )
    if metadata.get("available") is False:
        return EvidenceValidation(
            evidence.evidence_id,
            EVIDENCE_STATUS_UNAVAILABLE,
            "evidence source is unavailable",
        )
    if explicit_status is not None:
        if not isinstance(explicit_status, str):
            return EvidenceValidation(evidence.evidence_id, EVIDENCE_STATUS_INVALID, "evidence status is malformed")
        status = explicit_status.strip().casefold().replace("-", "_").replace(" ", "_")
        if status in {"ok", "success", "ready", "verified", "complete", "completed"}:
            status = EVIDENCE_STATUS_AVAILABLE
        if status not in EVIDENCE_STATUSES:
            return EvidenceValidation(evidence.evidence_id, EVIDENCE_STATUS_INVALID, "evidence status is unsupported")
        if status != EVIDENCE_STATUS_AVAILABLE:
            return EvidenceValidation(evidence.evidence_id, status, f"evidence is marked {status}")

    if evidence.sha256 is not None and _SHA256.fullmatch(evidence.sha256) is None:
        return EvidenceValidation(evidence.evidence_id, EVIDENCE_STATUS_INVALID, "evidence sha256 is malformed")
    file_digest = _metadata_digest(metadata, "file_sha256", "source_sha256")
    if file_digest == "":
        return EvidenceValidation(evidence.evidence_id, EVIDENCE_STATUS_INVALID, "source file sha256 is malformed")
    input_digest = _metadata_digest(metadata, "input_manifest_digest")
    if input_digest == "":
        return EvidenceValidation(
            evidence.evidence_id,
            EVIDENCE_STATUS_INVALID,
            "input manifest digest is malformed",
        )
    if expected_input_manifest_digest is not None and input_digest != expected_input_manifest_digest:
        return EvidenceValidation(
            evidence.evidence_id,
            EVIDENCE_STATUS_STALE,
            "evidence input manifest does not match the expected input",
        )

    if expected_file_sha256_by_path:
        path = metadata.get("path", metadata.get("relative_path", metadata.get("file")))
        normalized_path = str(path).replace("\\", "/").casefold() if isinstance(path, str) else ""
        expected_file_digest = expected_file_sha256_by_path.get(normalized_path)
        if expected_file_digest is None or file_digest != expected_file_digest:
            return EvidenceValidation(
                evidence.evidence_id,
                EVIDENCE_STATUS_STALE,
                "evidence source file does not match the expected SHA-256",
            )

    rule_digest = _metadata_digest(metadata, "rule_bundle_digest")
    if rule_digest == "":
        return EvidenceValidation(
            evidence.evidence_id,
            EVIDENCE_STATUS_INVALID,
            "rule bundle digest is malformed",
        )
    if expected_rule_bundle_digests:
        tool = str(metadata.get("tool_name", metadata.get("source", "*"))).casefold()
        expected_rule_digest = expected_rule_bundle_digests.get(tool, expected_rule_bundle_digests.get("*"))
        if expected_rule_digest is not None and rule_digest != expected_rule_digest:
            return EvidenceValidation(
                evidence.evidence_id,
                EVIDENCE_STATUS_STALE,
                "evidence rule bundle does not match the expected digest",
            )
    return EvidenceValidation(evidence.evidence_id)


def _required_evidence_ids(finding: Finding) -> tuple[set[str], bool]:
    for key in ("required_support_evidence_ids", "required_evidence_ids"):
        if key not in finding.raw:
            continue
        raw = finding.raw[key]
        if isinstance(raw, str):
            return {raw}, True
        if isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray, str)):
            return {item for item in raw if isinstance(item, str)}, True
        return set(), True
    return set(), False
