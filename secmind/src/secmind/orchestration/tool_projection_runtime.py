"""Immutable execution-coverage projection owned by the tool runtime."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from secmind.artifact_store import ArtifactStoreError
from secmind.investigation.contracts import ArtifactDataClass, ArtifactSecurityLabel, ArtifactView
from secmind.ledger import canonical_json
from secmind.schemas import AgentState, DataView, Evidence, StepPatch, ToolResult, WorkItem


def coverage_evidence(host: Any, item: WorkItem, result: ToolResult, patch: StepPatch) -> Evidence:
    actual_tool_name = patch.actual_tool_name
    actual_tool_version = patch.actual_tool_version
    if host.investigation_store is not None and item.step_run_id is not None:
        if result.invocation_id is None:
            raise RuntimeError("durable execution result has no invocation id")
        identity = host.investigation_store.execution_identity(result.invocation_id, run_id=item.run_id)
        output_digest = hashlib.sha256(canonical_json(result.model_dump(mode="json")).encode()).hexdigest()
        if (
            identity is None
            or identity.step_run_id != item.step_run_id
            or identity.run_fence != item.run_fence
            or identity.step_fence != item.step_fence
            or identity.output_digest != output_digest
        ):
            raise RuntimeError("durable execution identity does not match run/step/fence/output")
        if (
            actual_tool_name is not None
            and actual_tool_name != identity.actual_tool_name
            or actual_tool_version is not None
            and actual_tool_version != identity.actual_tool_version
        ):
            raise RuntimeError("worker patch conflicts with the durable actual tool identity")
        actual_tool_name = identity.actual_tool_name
        actual_tool_version = identity.actual_tool_version
    if actual_tool_name is None or actual_tool_version is None:
        raise RuntimeError("actual tool identity is unavailable")
    if actual_tool_name not in set(item.capability_candidates or [item.tool_name]):
        raise RuntimeError("actual tool is outside the authorized candidate set")
    actual_manifest = host.broker.registry.get(actual_tool_name).manifest
    if actual_manifest.version != actual_tool_version:
        raise RuntimeError("actual tool version is outside the active manifest catalog")
    coverage_payload = json.dumps(
        {
            "invocation_id": result.invocation_id,
            "run_id": item.run_id,
            "step_id": item.step_id,
            "tool_name": actual_tool_name,
            "tool_version": actual_tool_version,
            "status": result.status.value,
            "summary": result.summary,
            "duration_ms": result.duration_ms,
            "knowledge_refs": list(item.knowledge_refs),
            "signed_skill_refs": list(item.signed_skill_refs),
            "context_pack_digest": item.context_pack_digest,
            "context_influence_digest": item.context_influence_digest,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    stored = host.artifact_store.put(
        coverage_payload,
        media_type="application/vnd.secmind.step-coverage+json",
        run_id=item.run_id,
        data_view=DataView.OBSERVABLE,
    )
    if host.investigation_store is not None:
        host.investigation_store.label_artifact(
            ArtifactSecurityLabel(
                artifact_id=stored.artifact_id,
                owner_run_id=item.run_id,
                owner_step_id=item.step_id,
                owner_invocation_id=result.invocation_id,
                view=ArtifactView.OBSERVABLE,
                data_class=ArtifactDataClass.TOOL_OUTPUT,
                retention_policy_id="competition-run-default",
                allowed_purposes=["analysis", "report", "download"],
                created_by="orchestrator-coverage-projection",
                content_sha256=stored.sha256,
                size=stored.size_bytes,
                media_type=stored.media_type,
            )
        )
    return Evidence(
        evidence_id=f"coverage-{item.transition_id[:24]}",
        source=f"{actual_tool_name}:{actual_tool_version}",
        summary=f"{item.step_id} completed within its bounded tool invocation.",
        artifact_ref=stored.artifact_id,
        sha256=stored.sha256,
        metadata={
            "evidence_type": "execution_coverage",
            "tool_name": actual_tool_name,
            "tool_version": actual_tool_version,
            "step_id": item.step_id,
            "invocation_id": result.invocation_id,
            "knowledge_refs": list(item.knowledge_refs),
            "signed_skill_refs": list(item.signed_skill_refs),
            "context_pack_digest": item.context_pack_digest,
            "context_influence_digest": item.context_influence_digest,
        },
    )


def persist_projection_artifact(
    host: Any,
    state: AgentState,
    payload: dict[str, Any],
    *,
    media_type: str,
    reference_key: str,
) -> Any:
    """Persist one immutable report projection and enforce append-only identity."""

    content = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    stored = host.artifact_store.put(
        content,
        media_type=media_type,
        run_id=state.run_id,
        data_view=DataView.RAW_RESTRICTED,
    )
    existing = state.audit_coverage.get(reference_key)
    if existing is not None and str(existing) != stored.artifact_id:
        raise ArtifactStoreError(f"{reference_key} is append-only and cannot be overwritten")
    return stored


def verify_evidence_artifacts(host: Any, evidence: list[Evidence]) -> bool:
    for item in evidence:
        if item.artifact_ref is None or item.sha256 is None:
            return False
        try:
            content = host.artifact_store.read(item.artifact_ref)
        except (OSError, ValueError):
            return False
        if hashlib.sha256(content).hexdigest() != item.sha256.lower():
            return False
    return True


def verify_primary_receipt_artifact(host: Any, state: AgentState) -> bool:
    """Verify the raw provider bytes that back a published Primary lane."""

    if state.published_baseline is None:
        return True
    receipt = state.raw_primary_receipt
    if receipt is None or receipt.run_id != state.run_id or receipt.response_artifact_id != receipt.response_sha256:
        return False
    try:
        # ContentAddressedArtifactStore.read verifies both size and digest
        # against the artifact id while streaming from disk.
        host.artifact_store.read(receipt.response_artifact_id)
    except (OSError, ValueError):
        return False
    return True


__all__ = [
    "coverage_evidence",
    "persist_projection_artifact",
    "verify_evidence_artifacts",
    "verify_primary_receipt_artifact",
]
