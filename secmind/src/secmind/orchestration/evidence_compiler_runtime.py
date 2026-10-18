"""Deterministic parser-fact and Git-LFS evidence compilation node."""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from secmind.artifact_store import ArtifactStoreError
from secmind.domain_answers import EvidenceGapAnswer
from secmind.orchestration.domain_projection import (
    attach_semantic_delta,
    build_scenario_semantic_projection,
    record_scenario_semantic_projection,
)
from secmind.orchestration.primary_runtime import record_pre_primary_scenario_result
from secmind.schemas import (
    AgentReport,
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
    RunStatus,
)
from secmind.task_contract import EvidenceCompilerReceipt, EvidenceFact, canonical_digest

_GIT_LFS_POINTER = re.compile(
    rb"\A(Version|version) https://git-lfs\.github\.com/spec/v1\r?\n"
    rb"oid sha256:([a-f0-9]{64})\r?\nsize ([0-9]{1,20})\r?\n?\Z"
)


def _validation_issue_details(exc: ValidationError, *, limit: int = 16) -> list[dict[str, Any]]:
    """Return bounded, input-free diagnostics for the evidence compiler."""

    return [
        {
            "location": [str(part) for part in issue.get("loc", ())],
            "type": str(issue.get("type") or "validation_error"),
        }
        for issue in exc.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[:limit]
    ]


def _publish_lfs_evidence_gap(state: AgentState) -> None:
    """Publish a complete typed gap when immutable bytes are only an LFS pointer."""

    contract = state.resolved_task_contract
    rows = [item for item in state.evidence if item.metadata.get("evidence_type") == "git_lfs_pointer"]
    if contract is None or contract.scoring_mode != "evidence_gap" or not rows:
        return
    evidence_by_id = {item.evidence_id: item for item in rows}
    evidence_ids = sorted(evidence_by_id)
    observations = [
        {
            "observation_type": "git_lfs_pointer",
            "relative_path": item.metadata.get("relative_path"),
            "pointer_oid": item.metadata.get("pointer_oid"),
            "declared_size": item.metadata.get("declared_size"),
            "underlying_object_present": False,
            "attribution_permitted": False,
            "evidence_ids": [item.evidence_id],
            "source_locator": item.metadata.get("source_locator"),
        }
        for item in sorted(rows, key=lambda value: value.evidence_id)
    ]
    first_locator = observations[0]["source_locator"]
    answer = EvidenceGapAnswer.model_validate(
        {
            "task_id": contract.client_request_id or state.run_id,
            "execution_status": "success",
            "epistemic_status": "insufficient_evidence",
            "executive_summary": (
                "The supplied artifact is a Git LFS pointer and the referenced object is absent; "
                "content-level attribution is therefore not permitted."
            ),
            "limitations": ["The underlying Git LFS object was not supplied in the immutable input manifest."],
            "observations": observations,
            "known": [{"fact": "git_lfs_pointer_present", "evidence_ids": evidence_ids}],
            "unknown_fields": ["underlying_object_content", "content_attribution"],
            "blocked_claims": [
                {
                    "claim": "content-level attribution",
                    "reason": "underlying_lfs_object_absent",
                    "evidence_ids": evidence_ids,
                    "source_locator": first_locator,
                }
            ],
            "next_evidence": [
                {
                    "request": "Retrieve and digest-verify each declared Git LFS object.",
                    "evidence_ids": evidence_ids,
                    "source_locator": first_locator,
                }
            ],
            "extensions": {
                "coverage": {
                    "lfs_pointer_count": len(observations),
                    "underlying_object_available": False,
                    "network_access_performed": False,
                    "model_calls": 0,
                },
                "raw_artifact_digests": sorted({str(item.sha256).lower() for item in rows if item.sha256}),
            },
        }
    )
    output, delta = build_scenario_semantic_projection(
        state,
        answer,
        scenario="evidence_gap",
        operation="git_lfs_evidence_gap_compilation",
        evidence_by_id=evidence_by_id,
        parser_id="git-lfs-pointer",
        parser_version="1.0",
    )
    answer = attach_semantic_delta(answer, output, delta)
    record_scenario_semantic_projection(state, answer)
    state.status = RunStatus.COMPLETED
    state.report = AgentReport(
        run_id=state.run_id,
        status=RunStatus.COMPLETED,
        executive_summary=answer.executive_summary,
        answer_type=answer.answer_kind,
        answer_payload=answer.model_dump(mode="json"),
        evidence=list(state.evidence),
        limitations=list(answer.limitations),
        coverage=dict(state.audit_coverage),
        claim_ids=[item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED],
    )
    record_pre_primary_scenario_result(state)


async def compile_evidence(host: Any, value: Any) -> Any:
    state: AgentState = host._state(value)
    contract = state.resolved_task_contract
    if contract is None:
        state.status = RunStatus.RECOVERY_REQUIRED
        state.last_error = "Evidence compilation requires a sealed ResolvedTaskContract"
        return await host._checkpoint(state, "evidence_compiler.contract_missing", {}, "report")
    if (
        state.evidence_compiler_receipt is not None
        and state.evidence_compiler_receipt.contract_digest == contract.contract_digest
    ):
        _publish_lfs_evidence_gap(state)
        return await host._checkpoint(
            state,
            "evidence_compiler.reused",
            {"output_digest": state.evidence_compiler_receipt.output_digest},
        )
    artifacts = {item.artifact_id: item for item in state.input_artifacts}
    facts: list[EvidenceFact] = []
    raw_window_refs: list[str] = []
    for asset in sorted(
        host.task_spec_repository.parsed_assets(state.run_id),
        key=lambda item: item.parsed_asset_id,
    ):
        artifact = artifacts.get(asset.artifact_id)
        if artifact is None:
            continue
        raw_window_refs.append(artifact.sha256.lower())
        fact_value: dict[str, Any] = {
            "asset_type": asset.asset_type,
            "parser_id": asset.parser_id,
            "parser_version": asset.parser_version,
            "relative_path": asset.relative_path,
            "metadata": asset.metadata,
            "hints": [item.model_dump(mode="json") for item in asset.hints],
            "diagnostics": list(asset.diagnostics),
        }
        facts.append(
            EvidenceFact(
                fact_id="fact-" + canonical_digest([asset.parsed_asset_id, fact_value])[:32],
                fact_type=f"parsed_asset.{asset.asset_type}",
                value=fact_value,
                source_ref=asset.relative_path,
                source_sha256=artifact.sha256.lower(),
                locator=asset.parsed_asset_id,
                confidence=max((item.confidence for item in asset.hints), default=1.0),
            )
        )
    existing_lfs_sources: set[str] = set()
    for artifact in sorted(state.input_artifacts, key=lambda item: item.relative_path.casefold()):
        if artifact.size_bytes > 4_096:
            continue
        try:
            content = host.artifact_store.read(artifact.sha256.lower())
        except (ArtifactStoreError, OSError, ValueError):
            continue
        match = _GIT_LFS_POINTER.fullmatch(content)
        if match is None:
            continue
        existing_lfs_sources.add(artifact.relative_path)
        fact_value = {
            "relative_path": artifact.relative_path,
            "pointer_oid": match.group(2).decode("ascii"),
            "declared_size": int(match.group(3)),
            "underlying_object_present": False,
            "attribution_permitted": False,
            "format_variant": match.group(1).decode("ascii"),
        }
        facts.append(
            EvidenceFact(
                fact_id="fact-" + canonical_digest(["git_lfs_pointer", fact_value])[:32],
                fact_type="artifact.git_lfs_pointer",
                value=fact_value,
                source_ref=artifact.relative_path,
                source_sha256=artifact.sha256.lower(),
                locator="whole-file",
                confidence=1.0,
            )
        )
        evidence_id = (
            "evidence-lfs-"
            + canonical_digest([artifact.sha256.lower(), artifact.relative_path, "git-lfs-pointer"])[:32]
        )
        evidence = Evidence(
            evidence_id=evidence_id,
            source="secmind:evidence-compiler:git-lfs@1.0",
            summary=(
                "The supplied file is a Git LFS pointer; its declared content object is absent, "
                "so content attribution is not permitted."
            ),
            artifact_ref=artifact.sha256.lower(),
            sha256=artifact.sha256.lower(),
            metadata={
                "evidence_type": "git_lfs_pointer",
                "assurance_level": "deterministic",
                "source_artifact_sha256": artifact.sha256.lower(),
                "source_locator": {
                    "source_ref": artifact.relative_path,
                    "segment_id": "git-lfs-pointer",
                    "record_number": 0,
                    "line_number": 1,
                    "byte_offset": 0,
                    "byte_length": artifact.size_bytes,
                    "locator_scope": "whole_file",
                    "artifact_sha256": artifact.sha256.lower(),
                },
                **fact_value,
            },
        )
        if all(item.evidence_id != evidence_id for item in state.evidence):
            state.evidence.append(evidence)
        claim_id = "claim-lfs-" + canonical_digest([evidence_id, "missing-object"])[:32]
        if all(item.claim_id != claim_id for item in state.claims):
            state.claims.append(
                Claim(
                    claim_id=claim_id,
                    claim_type="evidence_gap_observation",
                    statement=(
                        "The input is a Git LFS pointer and the underlying object is absent; "
                        "no content-level attribution can be made."
                    ),
                    subject_ref=artifact.relative_path,
                    status=ClaimStatus.VERIFIED,
                    confidence=1.0,
                    producer="evidence-compiler",
                )
            )
            state.evidence_links.append(
                EvidenceLink(
                    link_id="link-lfs-" + canonical_digest([claim_id, evidence_id])[:32],
                    claim_id=claim_id,
                    evidence_id=evidence_id,
                    relation=EvidenceRelation.SUPPORTS,
                    weight=1.0,
                    verifier_status=ClaimStatus.VERIFIED,
                    grader_id="deterministic-cas-digest-verifier",
                )
            )
        raw_window_refs.append(artifact.sha256.lower())
    if existing_lfs_sources:
        state.audit_coverage["deterministic_evidence_gaps"] = {
            "git_lfs_pointer_sources": sorted(existing_lfs_sources),
            "underlying_object_available": False,
        }
    unavailable = sorted(
        {
            f"{item.parser_id}:{item.status}:{diagnostic}"
            for item in host.task_spec_repository.parser_runs(state.run_id)
            if item.status in {"failed", "skipped", "partial"}
            for diagnostic in (item.diagnostics or ["no diagnostic"])
        }
    )
    receipt_payload = {
        "compiler_id": "secmind.evidence-compiler",
        "compiler_version": "1.0",
        "run_id": state.run_id,
        "contract_digest": contract.contract_digest,
        "input_manifest_digest": contract.input_manifest_digest,
        "facts": [item.model_dump(mode="json") for item in facts],
        "raw_window_refs": sorted(set(raw_window_refs)),
        "unavailable_parts": unavailable,
        "truncated_count": 0,
        "dropped_ids": [],
    }
    try:
        state.evidence_compiler_receipt = EvidenceCompilerReceipt.model_validate(
            {**receipt_payload, "output_digest": canonical_digest(receipt_payload)}
        )
    except ValidationError as exc:
        # Parser facts and deterministic LFS observations have already been
        # validated and attached to state above.  Do not replay the whole run
        # when only the aggregate receipt projection is malformed; preserve
        # those facts and let the task-level Primary continue with a bounded
        # diagnostic route.
        retained_lfs_facts = [
            item.model_dump(mode="json") for item in facts if item.fact_type == "artifact.git_lfs_pointer"
        ]
        diagnostics = _validation_issue_details(exc)
        state.evidence_compiler_receipt = None
        state.status = (
            RunStatus.PARTIAL
            if state.status not in {RunStatus.DENIED, RunStatus.CANCELLED, RunStatus.FAILED}
            else state.status
        )
        state.last_error = "Evidence compiler receipt validation failed safely; deterministic facts were retained"
        state.audit_coverage["evidence_compiler_validation_failure"] = {
            "error_type": "ValidationError",
            "failure_stage": "evidence_compiler_receipt",
            "issue_count": exc.error_count(),
            "issues": diagnostics,
            "retained_lfs_facts": retained_lfs_facts,
            "retained_fact_count": len(facts),
            "raw_receipt_preserved": False,
            "recovery_route": "primary",
        }
        return await host._checkpoint(
            state,
            "evidence_compiler.degraded",
            state.audit_coverage["evidence_compiler_validation_failure"],
            "primary",
        )
    state.audit_coverage["evidence_compiler"] = {
        "version": state.evidence_compiler_receipt.compiler_version,
        "fact_count": len(facts),
        "unavailable_count": len(unavailable),
        "output_digest": state.evidence_compiler_receipt.output_digest,
        "pre_primary": True,
    }
    _publish_lfs_evidence_gap(state)
    return await host._checkpoint(state, "evidence_compiler.completed", state.audit_coverage["evidence_compiler"])


def append_verified_scenario_evidence(state: AgentState) -> None:
    """Attach bounded, verified compiler/scenario evidence to the sealed report."""

    if state.report is None:
        return
    scenario_claims = sorted(
        (
            claim
            for claim in state.claims
            if claim.producer in {"deterministic-scenario-analyzer", "evidence-compiler"}
            and claim.status == ClaimStatus.VERIFIED
        ),
        key=lambda claim: (
            0 if claim.claim_type == "exact_value_observed" else 1,
            0 if claim.claim_type in {"suspicious_event", "ioc_observed"} else 1,
            claim.claim_id,
        ),
    )[:256]
    scenario_claim_ids = {claim.claim_id for claim in scenario_claims}
    scenario_evidence_ids = {
        link.evidence_id
        for link in state.evidence_links
        if link.claim_id in scenario_claim_ids
        and link.relation == EvidenceRelation.SUPPORTS
        and link.verifier_status == ClaimStatus.VERIFIED
    }
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    report_evidence = {item.evidence_id: item for item in state.report.evidence}
    report_evidence.update(
        {
            evidence_id: evidence_by_id[evidence_id]
            for evidence_id in sorted(scenario_evidence_ids)
            if evidence_id in evidence_by_id
        }
    )
    state.report = state.report.model_copy(
        update={
            "evidence": sorted(report_evidence.values(), key=lambda item: item.evidence_id),
            "claim_ids": sorted(scenario_claim_ids),
        }
    )


__all__ = ["append_verified_scenario_evidence", "compile_evidence"]
