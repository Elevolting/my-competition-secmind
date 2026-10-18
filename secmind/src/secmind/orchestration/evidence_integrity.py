"""CAS-bound evidence projection helpers for the orchestration graph."""

from __future__ import annotations

import hashlib

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.canonical_primary import CanonicalProjection
from secmind.evidence_graph import make_claim, make_link
from secmind.schemas import (
    SCHEMA_VERSION,
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
)


def bind_canonical_baseline_claims(
    state: AgentState,
    projection: CanonicalProjection,
    artifact_store: ContentAddressedArtifactStore,
) -> None:
    """Bind Primary claims to immutable input bytes without asserting semantics."""

    artifacts_by_sha = {item.sha256.lower(): item for item in state.input_artifacts}
    evidence_by_id = {item.evidence_id: item for item in projection.evidence}
    claims: list[Claim] = []
    links: list[EvidenceLink] = []
    confidence_values = {"HIGH": 0.95, "MEDIUM": 0.75, "LOW": 0.4, "UNKNOWN": 0.0}
    for finding in projection.findings:
        if finding.path in {"", "."} or not finding.evidence_ids:
            continue
        bound_evidence: list[Evidence] = []
        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            artifact = (
                artifacts_by_sha.get(evidence.artifact_ref.lower())
                if evidence is not None and evidence.artifact_ref is not None
                else None
            )
            if evidence is None or artifact is None or evidence.sha256 != artifact.sha256:
                bound_evidence = []
                break
            artifact_path = artifact.relative_path.replace("\\", "/")
            if artifact_path != finding.path and not artifact_path.endswith("/" + finding.path):
                bound_evidence = []
                break
            if finding.line is not None:
                try:
                    source_bytes = artifact_store.read(artifact.sha256.lower())
                except (ArtifactStoreError, OSError, ValueError):
                    bound_evidence = []
                    break
                if hashlib.sha256(source_bytes).hexdigest() != artifact.sha256.lower():
                    bound_evidence = []
                    break
                line_count = len(source_bytes.decode("utf-8", errors="replace").splitlines())
                if finding.line > line_count:
                    bound_evidence = []
                    break
            bound_evidence.append(evidence)
        if not bound_evidence:
            continue
        claim = make_claim(
            claim_type="canonical_primary.baseline_binding",
            statement=(
                f"Primary finding {finding.finding_id} is bound to immutable input bytes; "
                "its semantic assurance remains model-proposed."
            ),
            subject_ref=finding.finding_id,
            producer="canonical-primary",
            severity=finding.severity,
            confidence=confidence_values[finding.confidence],
            version=SCHEMA_VERSION,
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
        claims.append(claim)
        links.extend(
            make_link(
                claim_id=claim.claim_id,
                evidence_id=item.evidence_id,
                relation=EvidenceRelation.SUPPORTS,
                grader_id="canonical-input-binding-v1",
            ).model_copy(update={"verifier_status": ClaimStatus.VERIFIED})
            for item in bound_evidence
        )
    for evidence in projection.evidence:
        if evidence.metadata.get("evidence_type") != "canonical_primary_domain_reference":
            continue
        artifact = artifacts_by_sha.get(evidence.artifact_ref.lower()) if evidence.artifact_ref is not None else None
        if artifact is None or evidence.sha256 != artifact.sha256:
            continue
        claim = make_claim(
            claim_type="canonical_primary.domain_answer_binding",
            statement=(
                "A typed domain-answer observation is bound to immutable input bytes; "
                "its semantic assurance remains model-proposed."
            ),
            subject_ref=f"domain-answer:{evidence.evidence_id}",
            producer="canonical-primary",
            confidence=0.75,
            version=SCHEMA_VERSION,
        ).model_copy(update={"status": ClaimStatus.VERIFIED})
        claims.append(claim)
        links.append(
            make_link(
                claim_id=claim.claim_id,
                evidence_id=evidence.evidence_id,
                relation=EvidenceRelation.SUPPORTS,
                grader_id="canonical-input-binding-v1",
            ).model_copy(update={"verifier_status": ClaimStatus.VERIFIED})
        )
    state.claims = sorted(
        {item.claim_id: item for item in [*state.claims, *claims]}.values(),
        key=lambda item: item.claim_id,
    )
    state.evidence_links = sorted(
        {item.link_id: item for item in [*state.evidence_links, *links]}.values(),
        key=lambda item: item.link_id,
    )


__all__ = ["bind_canonical_baseline_claims"]
