"""Durable raw-response receipt operations."""

from __future__ import annotations

import hashlib

from pydantic import ValidationError

from secmind.artifact_store import ArtifactStoreError
from secmind.investigation.store import InvestigationConflict
from secmind.model_gateway.contracts import (
    DurableReceiptError,
    ProviderAttempt,
    RawModelResponseReceipt,
)
from secmind.model_gateway.identity import raw_response_slot_id
from secmind.schemas import DataView, ModelUsage

RAW_RESPONSE_OBJECT_TYPE = "model.raw_response_receipt.v1"
RAW_RESPONSE_MEDIA_TYPE = "application/vnd.secmind.raw-model-response+json"


def load_raw_response_receipt(
    gateway,
    *,
    run_id: str,
    logical_call_id: str,
    model_id: str,
    candidate_index: int,
    repair_index: int,
    request_sha256: str,
    provider_request_sha256: str,
    response_schema_sha256: str,
    prompt_version: str,
    prompt_artifact_id: str | None,
    prompt_selection_digest: str | None,
    prompt_optimizer_attempt_id: str | None,
    prompt_lineage_reason: str,
    parent_logical_call_id: str | None,
    lineage_stage: str,
) -> RawModelResponseReceipt | None:
    if gateway._usage_store is None or gateway._artifact_store is None:
        return None
    slot_id = raw_response_slot_id(
        run_id=run_id,
        logical_call_id=logical_call_id,
        model_id=model_id,
        candidate_index=candidate_index,
        repair_index=repair_index,
        provider_request_sha256=provider_request_sha256,
    )
    try:
        rows = gateway._usage_store.list_objects(run_id, RAW_RESPONSE_OBJECT_TYPE)
    except Exception as exc:
        raise DurableReceiptError("durable raw response receipt lookup failed") from exc
    matching = [row for row in rows if row.get("slot_id") == slot_id]
    if not matching:
        return None
    if len(matching) != 1:
        raise DurableReceiptError("durable raw response slot is ambiguous")
    try:
        receipt = RawModelResponseReceipt.model_validate(matching[0])
    except ValidationError as exc:
        raise DurableReceiptError("durable raw response receipt is invalid") from exc
    if (
        receipt.run_id != run_id
        or receipt.logical_call_id != logical_call_id
        or receipt.model_id != model_id
        or receipt.candidate_index != candidate_index
        or receipt.repair_index != repair_index
        or receipt.request_sha256 != request_sha256
        or receipt.provider_request_sha256 != provider_request_sha256
        or receipt.response_schema_sha256 != response_schema_sha256
        or receipt.prompt_version != prompt_version
        or receipt.prompt_artifact_id != prompt_artifact_id
        or (receipt.prompt_selection_digest is not None and receipt.prompt_selection_digest != prompt_selection_digest)
        or (
            receipt.prompt_optimizer_attempt_id is not None
            and receipt.prompt_optimizer_attempt_id != prompt_optimizer_attempt_id
        )
        or (
            receipt.prompt_lineage_reason != "legacy_unbound_prompt"
            and receipt.prompt_lineage_reason != prompt_lineage_reason
        )
        or (receipt.parent_logical_call_id is not None and receipt.parent_logical_call_id != parent_logical_call_id)
        or (receipt.lineage_stage != "legacy" and receipt.lineage_stage != lineage_stage)
    ):
        raise DurableReceiptError("durable raw response receipt binding is invalid")
    # Verify access classification and bytes before treating the database
    # pointer as a reusable paid response.
    gateway._read_raw_response(receipt)
    return receipt


def persist_raw_response_receipt(
    gateway,
    *,
    raw: str,
    run_id: str,
    logical_call_id: str,
    provider_attempt: ProviderAttempt,
    model_id: str,
    candidate_index: int,
    repair_index: int,
    request_sha256: str,
    provider_request_sha256: str,
    response_schema_sha256: str,
    prompt_version: str,
    prompt_artifact_id: str | None,
    prompt_selection_digest: str | None,
    prompt_optimizer_attempt_id: str | None,
    prompt_lineage_reason: str,
    parent_logical_call_id: str | None,
    lineage_stage: str,
    duration_ms: int,
    used_fallback: bool,
    usage: ModelUsage,
    provider_reported_usage: ModelUsage,
    conservative_reserved_usage: ModelUsage,
    unknown_usage_attempts: int,
) -> RawModelResponseReceipt | None:
    if gateway._usage_store is None or gateway._artifact_store is None:
        return None
    raw_bytes = raw.encode("utf-8")
    response_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        artifact = gateway._artifact_store.put(
            raw_bytes,
            expected_sha256=response_sha256,
            media_type=RAW_RESPONSE_MEDIA_TYPE,
            run_id=run_id,
            data_view=DataView.RAW_RESTRICTED,
        )
    except (ArtifactStoreError, OSError) as exc:
        raise DurableReceiptError("raw model response could not be stored safely") from exc
    slot_id = raw_response_slot_id(
        run_id=run_id,
        logical_call_id=logical_call_id,
        model_id=model_id,
        candidate_index=candidate_index,
        repair_index=repair_index,
        provider_request_sha256=provider_request_sha256,
    )
    receipt = RawModelResponseReceipt.create(
        slot_id=slot_id,
        run_id=run_id,
        logical_call_id=logical_call_id,
        provider_request_id=provider_attempt.provider_request_id,
        model_id=model_id,
        candidate_index=candidate_index,
        repair_index=repair_index,
        request_sha256=request_sha256,
        provider_request_sha256=provider_request_sha256,
        response_sha256=response_sha256,
        response_artifact_id=artifact.artifact_id,
        response_schema_sha256=response_schema_sha256,
        prompt_version=prompt_version,
        prompt_artifact_id=prompt_artifact_id,
        prompt_selection_digest=prompt_selection_digest,
        prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
        prompt_lineage_reason=prompt_lineage_reason,
        parent_logical_call_id=parent_logical_call_id,
        lineage_stage=lineage_stage,
        duration_ms=duration_ms,
        used_fallback=used_fallback,
        usage=usage,
        provider_reported_usage=provider_reported_usage,
        conservative_reserved_usage=conservative_reserved_usage,
        unknown_usage_attempts=unknown_usage_attempts,
    )
    try:
        gateway._usage_store.put_object(
            receipt,
            run_id=run_id,
            object_type=RAW_RESPONSE_OBJECT_TYPE,
            object_id=receipt.receipt_id,
            logical_key=slot_id,
            content_digest=receipt.receipt_id.removeprefix("raw-model-response-"),
        )
        return receipt
    except InvestigationConflict:
        # A current owner may have completed the same deterministic slot.
        # Never parse the losing response; reuse and verify the winner.
        winner = gateway._load_raw_response_receipt(
            run_id=run_id,
            logical_call_id=logical_call_id,
            model_id=model_id,
            candidate_index=candidate_index,
            repair_index=repair_index,
            request_sha256=request_sha256,
            provider_request_sha256=provider_request_sha256,
            response_schema_sha256=response_schema_sha256,
            prompt_version=prompt_version,
            prompt_artifact_id=prompt_artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            lineage_stage=lineage_stage,
        )
        if winner is None:  # pragma: no cover - conflict implies an existing logical slot
            raise DurableReceiptError("raw response receipt conflict has no durable winner") from None
        return winner
    except Exception as exc:
        raise DurableReceiptError("raw model response receipt commit failed") from exc


def read_raw_response(gateway, receipt: RawModelResponseReceipt) -> str:
    if gateway._artifact_store is None:
        raise DurableReceiptError("raw response artifact store is unavailable")
    try:
        metadata = gateway._artifact_store.metadata_for(receipt.response_artifact_id)
        if metadata.data_view != DataView.RAW_RESTRICTED or receipt.run_id not in metadata.run_ids:
            raise DurableReceiptError("raw response artifact access binding is invalid")
        raw_bytes = gateway._artifact_store.read(receipt.response_artifact_id)
    except DurableReceiptError:
        raise
    except (ArtifactStoreError, FileNotFoundError, OSError) as exc:
        raise DurableReceiptError("raw response artifact is missing or corrupt") from exc
    observed = hashlib.sha256(raw_bytes).hexdigest()
    if observed != receipt.response_sha256 or observed != receipt.response_artifact_id:
        raise DurableReceiptError("raw response artifact digest is invalid")
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - provider content is a Python str
        raise DurableReceiptError("raw response artifact is not UTF-8") from exc
