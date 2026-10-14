from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from secmind.evidence_graph import EvidenceGraph
from secmind.outcomes import GradeContext, GradeResult, GraderRegistry
from secmind.schemas import (
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceAssurance,
    EvidenceRelation,
    Finding,
    OutcomeContract,
    VerificationResult,
)


def _valid_sha256(value: str | None) -> bool:
    return value is not None and len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)


def _normalize_repository_path(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not normalized or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class RepositoryFile:
    path: str
    sha256: str
    line_count: int

    def __post_init__(self) -> None:
        normalized = _normalize_repository_path(self.path)
        if normalized is None:
            raise ValueError(f"Unsafe repository path: {self.path!r}")
        if not _valid_sha256(self.sha256):
            raise ValueError("Repository file hash must be a SHA-256 digest")
        if self.line_count < 0:
            raise ValueError("Repository line count cannot be negative")
        object.__setattr__(self, "path", normalized)
        object.__setattr__(self, "sha256", self.sha256.lower())


@dataclass(frozen=True)
class VerificationContext:
    repository_files: Mapping[str, RepositoryFile] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    evidence_hashes: Mapping[str, str] = field(default_factory=dict)
    artifact_hashes: Mapping[str, str] = field(default_factory=dict)
    coverage_by_step: Mapping[str, dict[str, Any]] = field(default_factory=dict)
    approved_rule_digests: frozenset[str] = frozenset()
    approved_advisory_digests: frozenset[str] = frozenset()
    claim_contract_ids: Mapping[str, str] = field(default_factory=dict)
    prior_results: Mapping[str, VerificationResult] = field(default_factory=dict)
    supplement_round: int = 0
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.supplement_round < 0:
            raise ValueError("supplement_round cannot be negative")


@dataclass(frozen=True)
class VerificationBatch:
    graph: EvidenceGraph
    results: tuple[VerificationResult, ...]
    grade_results: Mapping[str, tuple[GradeResult, ...]]
    contract_grade_results: Mapping[str, tuple[GradeResult, ...]]
    supplement_requests: Mapping[str, tuple[str, ...]]
    supplement_round: int
    supplement_exhausted: bool

    @property
    def needs_supplement(self) -> bool:
        return bool(self.supplement_requests) and not self.supplement_exhausted


class SkepticalVerifier:
    """Independent, deterministic integrity verifier for proposed security claims."""

    def __init__(self, registry: GraderRegistry | None = None, *, max_supplement_rounds: int = 2) -> None:
        if max_supplement_rounds < 0:
            raise ValueError("max_supplement_rounds cannot be negative")
        self.registry = registry or GraderRegistry()
        self.max_supplement_rounds = max_supplement_rounds

    def verify(
        self,
        graph: EvidenceGraph,
        contracts: tuple[OutcomeContract, ...],
        context: VerificationContext,
    ) -> VerificationBatch:
        verified_graph = EvidenceGraph(claims=graph.claims, evidence=graph.evidence, links=graph.links)
        contract_by_id = {contract.contract_id: contract for contract in contracts}
        contract_by_step = {contract.step_id: contract for contract in contracts}
        results: list[VerificationResult] = []
        grades_by_claim: dict[str, tuple[GradeResult, ...]] = {}
        grades_by_contract: dict[str, list[GradeResult]] = {}
        supplement_requests: dict[str, tuple[str, ...]] = {}
        exhausted = context.supplement_round >= self.max_supplement_rounds

        for claim in graph.claims:
            if claim.status in {ClaimStatus.VERIFIED, ClaimStatus.REJECTED, ClaimStatus.CONFLICTED}:
                current_digest = self._evidence_set_digest(claim.claim_id, graph)
                prior = context.prior_results.get(claim.claim_id)
                if prior is None or prior.evidence_set_digest == current_digest:
                    results.append(self._existing_result(claim, graph, current_digest=current_digest))
                    continue
            contract_id = context.claim_contract_ids.get(claim.claim_id)
            contract = contract_by_id.get(contract_id) if contract_id else contract_by_step.get(claim.producer)
            result, grades = self._verify_claim(claim, graph, contract, context)
            grades_by_claim[claim.claim_id] = grades
            if contract is not None:
                grades_by_contract.setdefault(contract.contract_id, []).extend(grades)
            results.append(result)

            if result.status == ClaimStatus.INSUFFICIENT:
                requested = tuple(sorted(set(result.requested_evidence_types or ["supporting_evidence"])))
                supplement_requests[claim.claim_id] = requested
                if not exhausted:
                    # INSUFFICIENT becomes terminal only after the bounded supplement budget is exhausted.
                    continue
            verified_graph.apply_verification(result)

        return VerificationBatch(
            graph=verified_graph,
            results=tuple(sorted(results, key=lambda item: item.claim_id)),
            grade_results={key: grades_by_claim[key] for key in sorted(grades_by_claim)},
            contract_grade_results={key: tuple(grades_by_contract[key]) for key in sorted(grades_by_contract)},
            supplement_requests={key: supplement_requests[key] for key in sorted(supplement_requests)},
            supplement_round=context.supplement_round,
            supplement_exhausted=exhausted,
        )

    def _verify_claim(
        self,
        claim: Claim,
        graph: EvidenceGraph,
        contract: OutcomeContract | None,
        context: VerificationContext,
    ) -> tuple[VerificationResult, tuple[GradeResult, ...]]:
        links = graph.links_for_claim(claim.claim_id)
        supporting_links = tuple(link for link in links if link.relation == EvidenceRelation.SUPPORTS)
        linked_evidence = {item.evidence_id: item for item in graph.evidence_for_claim(claim.claim_id)}

        if any(link.relation == EvidenceRelation.INVALIDATES for link in links):
            return self._result(claim, ClaimStatus.REJECTED, "Claim is invalidated by linked evidence.", links), ()
        if any(link.relation == EvidenceRelation.CONTRADICTS for link in links):
            return self._result(claim, ClaimStatus.CONFLICTED, "Claim has contradictory evidence.", links), ()
        if contract is None:
            return self._result(claim, ClaimStatus.REJECTED, "Claim has no immutable outcome contract.", links), ()
        try:
            self.registry.validate_contract(contract)
        except ValueError as exc:
            return self._result(claim, ClaimStatus.REJECTED, str(exc), links), ()
        if claim.claim_type not in contract.expected_claim_types:
            return self._result(
                claim,
                ClaimStatus.REJECTED,
                f"Claim type {claim.claim_type!r} is outside its outcome contract.",
                links,
            ), ()
        if not supporting_links:
            requested = tuple(contract.required_evidence_types or ["supporting_evidence"])
            return self._result(
                claim,
                ClaimStatus.INSUFFICIENT,
                "Claim has no supporting evidence.",
                links,
                requested=requested,
            ), ()

        finding_error = self._validate_finding_location(claim, context)
        if finding_error:
            return self._result(claim, ClaimStatus.REJECTED, finding_error, links), ()

        supporting_evidence = tuple(linked_evidence[link.evidence_id] for link in supporting_links)
        integrity_errors = [
            error
            for evidence in supporting_evidence
            if (error := self._validate_evidence(evidence, context)) is not None
        ]
        evidence_types = frozenset(
            str(evidence.metadata.get("evidence_type", "unknown")) for evidence in supporting_evidence
        )
        tool_versions = self._tool_versions(supporting_evidence)
        grade_context = GradeContext(
            contract=contract,
            claim=claim,
            evidence=supporting_evidence,
            evidence_types=evidence_types,
            tool_versions=tool_versions,
            coverage=dict(context.coverage_by_step.get(contract.step_id, {})),
            integrity_valid=not integrity_errors,
        )
        grades = self.registry.grade(grade_context)
        grade_failures = tuple(item for item in grades if not item.passed)
        hard_failure = integrity_errors or any(
            item.grader_id in {"evidence-integrity", "tool-versions"} for item in grade_failures
        )
        if hard_failure:
            reasons = integrity_errors + [item.reason for item in grade_failures]
            return self._result(
                claim,
                ClaimStatus.REJECTED,
                " ".join(dict.fromkeys(reasons)),
                links,
                rejected=tuple(item.evidence_id for item in supporting_evidence),
                graders=tuple(item.grader_id for item in grades),
            ), grades
        if grade_failures:
            requested = tuple(sorted({value for item in grade_failures for value in item.requested_evidence_types}))
            return self._result(
                claim,
                ClaimStatus.INSUFFICIENT,
                " ".join(item.reason for item in grade_failures),
                links,
                requested=requested or ("contract_requirements",),
                graders=tuple(item.grader_id for item in grades),
            ), grades
        if self._requires_semantic_corroboration(claim):
            assurance = {
                str(item.metadata.get("assurance_level", EvidenceAssurance.MODEL_PROPOSED.value))
                for item in supporting_evidence
            }
            independently_supported = bool(
                assurance
                & {
                    EvidenceAssurance.SEMANTICALLY_CORROBORATED.value,
                    EvidenceAssurance.HUMAN_CONFIRMED.value,
                }
            )
            if not independently_supported:
                return self._result(
                    claim,
                    ClaimStatus.INSUFFICIENT,
                    "Model-proposed security finding lacks independent semantic corroboration.",
                    links,
                    requested=("independent_semantic_evidence",),
                    graders=tuple(item.grader_id for item in grades),
                ), grades
        return self._result(
            claim,
            ClaimStatus.VERIFIED,
            "Claim is supported by integrity-checked evidence and satisfies its outcome contract.",
            links,
            verified=tuple(item.evidence_id for item in supporting_evidence),
            graders=tuple(item.grader_id for item in grades),
        ), grades

    def _validate_finding_location(self, claim: Claim, context: VerificationContext) -> str | None:
        finding = next((item for item in context.findings if item.finding_id == claim.subject_ref), None)
        if finding is None:
            return None
        normalized = _normalize_repository_path(finding.path)
        if normalized is None:
            return "Finding path is unsafe or non-canonical."
        repository = {item.path: item for item in context.repository_files.values()}
        indexed = repository.get(normalized)
        if indexed is None:
            return "Finding path is absent from the immutable repository index."
        if finding.line is not None and (finding.line < 1 or finding.line > indexed.line_count):
            return "Finding line is outside the indexed file bounds."
        return None

    def _validate_evidence(self, evidence: Evidence, context: VerificationContext) -> str | None:
        expected_digest = evidence.sha256
        if expected_digest is None or not _valid_sha256(expected_digest):
            return f"Evidence {evidence.evidence_id} has no valid SHA-256 digest."
        actual = (
            context.artifact_hashes.get(evidence.artifact_ref)
            if evidence.artifact_ref is not None
            else context.evidence_hashes.get(evidence.evidence_id)
        )
        if not _valid_sha256(actual) or not hmac.compare_digest(expected_digest.lower(), str(actual).lower()):
            return f"Evidence {evidence.evidence_id} hash does not match its materialized content."
        expires_at = _parse_datetime(evidence.metadata.get("expires_at"))
        if expires_at is not None and expires_at <= context.now:
            return f"Evidence {evidence.evidence_id} uses expired rule or advisory data."
        rule_digest = evidence.metadata.get("rule_bundle_digest")
        if (
            context.approved_rule_digests
            and isinstance(rule_digest, str)
            and rule_digest not in context.approved_rule_digests
        ):
            return f"Evidence {evidence.evidence_id} uses an unapproved rule bundle."
        advisory_digest = evidence.metadata.get("advisory_db_digest")
        if (
            context.approved_advisory_digests
            and isinstance(advisory_digest, str)
            and advisory_digest not in context.approved_advisory_digests
        ):
            return f"Evidence {evidence.evidence_id} uses an unapproved advisory database."
        file_sha256 = evidence.metadata.get("file_sha256")
        path = evidence.metadata.get("path")
        if isinstance(file_sha256, str) and isinstance(path, str):
            normalized = _normalize_repository_path(path)
            indexed = None if normalized is None else context.repository_files.get(normalized)
            if indexed is None or not hmac.compare_digest(indexed.sha256, file_sha256.lower()):
                return f"Evidence {evidence.evidence_id} does not match the indexed source file."
        return None

    @staticmethod
    def _tool_versions(evidence: tuple[Evidence, ...]) -> dict[str, str]:
        versions: dict[str, str] = {}
        for item in evidence:
            tool = item.metadata.get("tool_name")
            version = item.metadata.get("tool_version")
            if not isinstance(tool, str) or not isinstance(version, str):
                source = item.source.rsplit(":", 1)
                if len(source) == 2:
                    tool, version = source
            if isinstance(tool, str) and isinstance(version, str):
                existing = versions.get(tool)
                versions[tool] = version if existing in {None, version} else "conflicted"
        return versions

    @staticmethod
    def _existing_result(
        claim: Claim,
        graph: EvidenceGraph,
        *,
        current_digest: str,
    ) -> VerificationResult:
        evidence_ids = tuple(item.evidence_id for item in graph.evidence_for_claim(claim.claim_id))
        return VerificationResult(
            claim_id=claim.claim_id,
            status=claim.status,
            reason_summary="Claim was already in a terminal verifier state.",
            verified_evidence_ids=list(evidence_ids) if claim.status == ClaimStatus.VERIFIED else [],
            rejected_evidence_ids=list(evidence_ids) if claim.status == ClaimStatus.REJECTED else [],
            confidence=claim.confidence,
            evidence_set_digest=current_digest,
        )

    @classmethod
    def _result(
        cls,
        claim: Claim,
        status: ClaimStatus,
        reason: str,
        links: tuple[Any, ...],
        *,
        verified: tuple[str, ...] = (),
        rejected: tuple[str, ...] = (),
        requested: tuple[str, ...] = (),
        graders: tuple[str, ...] = (),
    ) -> VerificationResult:
        linked_ids = {link.evidence_id for link in links}
        return VerificationResult(
            claim_id=claim.claim_id,
            status=status,
            reason_summary=reason,
            verified_evidence_ids=sorted(set(verified) & linked_ids),
            rejected_evidence_ids=sorted(set(rejected) & linked_ids),
            requested_evidence_types=sorted(set(requested)),
            confidence=claim.confidence if status == ClaimStatus.VERIFIED else 0,
            grader_ids=sorted(set(graders)),
            evidence_set_digest=cls._evidence_set_digest_from_links(links),
        )

    @staticmethod
    def _requires_semantic_corroboration(claim: Claim) -> bool:
        return claim.producer == "model-source-review" and claim.claim_type.endswith(".finding")

    @classmethod
    def _evidence_set_digest(cls, claim_id: str, graph: EvidenceGraph) -> str:
        # Evidence objects are immutable and content-addressed.  Link identity
        # therefore captures the evidence revision without duplicating bytes.
        return cls._evidence_set_digest_from_links(graph.links_for_claim(claim_id))

    @staticmethod
    def _evidence_set_digest_from_links(links: tuple[Any, ...]) -> str:
        payload = []
        for link in sorted(links, key=lambda item: (item.evidence_id, item.relation.value, item.link_id)):
            payload.append(
                {
                    "evidence_id": link.evidence_id,
                    "relation": link.relation.value,
                }
            )
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
