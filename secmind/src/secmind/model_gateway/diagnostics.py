"""Bounded, secret-free attempt diagnostics and failure capsules."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from typing import Any, Literal
from uuid import uuid4

import httpx
from pydantic import ValidationError

from secmind.investigation.contracts import UsageSettlement, seal_contract
from secmind.metrics import MODEL_REQUESTS, MODEL_TOKENS
from secmind.model_gateway.budget import bounded_usage_count
from secmind.model_gateway.contracts import (
    ModelAttemptSummary,
    ModelGatewayFailure,
    ModelResponseTooLargeError,
    ProviderAttempt,
)
from secmind.model_gateway.identity import canonical_sha256, legacy_selection_digest
from secmind.model_router import MODEL_ROUTER_VERSION, PRIMARY_ROUTE_PROFILE, ModelTaskKind
from secmind.schemas import ModelUsage

logger = logging.getLogger(__name__)


def summaries_for_call(
    provider_attempts: Iterable[ProviderAttempt],
    logical_call_id: str,
    *,
    extra: list[ModelAttemptSummary] | None = None,
) -> list[ModelAttemptSummary]:
    summaries = [item.summary() for item in provider_attempts if item.logical_call_id == logical_call_id]
    if extra:
        summaries.extend(extra)
    # A checkpoint retry or concurrent durable writer must not duplicate a
    # diagnostic stage in the public failure capsule.
    unique: dict[tuple[str | None, int, str], ModelAttemptSummary] = {}
    for item in summaries:
        unique[(item.provider_request_id, item.ordinal, item.stage)] = item
    return sorted(unique.values(), key=lambda item: (item.ordinal, item.stage))[:32]


def failure_category(summary: ModelAttemptSummary | None, last_error: BaseException | None) -> str:
    if summary is not None:
        if summary.status_code == 429:
            return "rate_limit"
        if summary.status_code == 408:
            return "timeout"
        if summary.status_code is not None and summary.status_code >= 500:
            return "http_5xx"
        if summary.stage == "schema_validation":
            return "schema"
        if summary.stage in {"connect", "pool", "write", "read_idle", "transport"}:
            return "transport" if summary.stage != "read_idle" else "timeout"
        if summary.error_type == "timeout":
            return "timeout"
        if summary.error_type in {"malformed_response", "parse"}:
            return "parse"
        if summary.error_type == "fallback_unavailable":
            return "fallback_unavailable"
        if summary.error_type:
            return summary.error_type
    if isinstance(last_error, (ValidationError, json.JSONDecodeError)):
        return "schema"
    if isinstance(last_error, (TimeoutError, httpx.TimeoutException)):
        return "timeout"
    if isinstance(last_error, httpx.TransportError):
        return "transport"
    if isinstance(last_error, ModelResponseTooLargeError):
        return "response_too_large"
    return "gateway"


def schema_failure_summary(
    attempts: list[ModelAttemptSummary],
    *,
    route: str,
    route_profile: str,
    model_id: str,
    prompt_version: str,
    deadline_ms: int,
    remaining_budget_ms: int,
    logical_call_id: str,
    parent_logical_call_id: str | None,
    prompt_optimizer_attempt_id: str | None,
    prompt_lineage_reason: str,
    lineage_stage: str,
    recovery_kind: str,
    recovery_independence: str,
) -> ModelAttemptSummary:
    previous = attempts[-1] if attempts else None
    return ModelAttemptSummary(
        ordinal=max((item.ordinal for item in attempts), default=0) + 1,
        provider_request_id=None if previous is None else previous.provider_request_id,
        stage="schema_validation",
        error_type="schema",
        status_code=None if previous is None else previous.status_code,
        duration_ms=0 if previous is None else previous.duration_ms,
        retryable=True,
        request_digest=None if previous is None else previous.request_digest,
        response_digest=None if previous is None else previous.response_digest,
        route=route,
        route_profile=route_profile,
        model_id=model_id,
        prompt_version=prompt_version,
        deadline_ms=deadline_ms,
        remaining_budget_ms=remaining_budget_ms,
        logical_call_id=logical_call_id,
        parent_logical_call_id=parent_logical_call_id,
        prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
        prompt_lineage_reason=prompt_lineage_reason,
        lineage_stage=lineage_stage,
        recovery_kind=recovery_kind,
        recovery_independence=recovery_independence,
    )


def build_failure(
    provider_attempts: Iterable[ProviderAttempt],
    *,
    logical_call_id: str,
    last_error: BaseException | None,
    route: str,
    route_profile: str,
    model_id: str,
    prompt_version: str,
    deadline_ms: int,
    deadline_at: float,
    fallback_status: str,
    recovery_kind: str = "primary",
    recovery_independence: str = "not_applicable",
    extra_attempts: list[ModelAttemptSummary] | None = None,
) -> ModelGatewayFailure:
    attempts = summaries_for_call(provider_attempts, logical_call_id, extra=extra_attempts)
    last_attempt = next(
        (item for item in reversed(attempts) if item.error_type != "fallback_unavailable"),
        attempts[-1] if attempts else None,
    )
    error_type = failure_category(last_attempt, last_error)
    status_code = None if last_attempt is None else last_attempt.status_code
    retryable = False if last_attempt is None else last_attempt.retryable
    request_digest = None if last_attempt is None else last_attempt.request_digest
    stage = "gateway" if last_attempt is None else last_attempt.stage
    budget_dimension = None if last_attempt is None else last_attempt.budget_dimension
    if last_attempt is not None:
        recovery_kind = last_attempt.recovery_kind
        recovery_independence = last_attempt.recovery_independence
    remaining_budget_ms = max(0, int((deadline_at - time.monotonic()) * 1000))
    failure_id = canonical_sha256(
        {
            "logical_call_id": logical_call_id,
            "error_type": error_type,
            "stage": stage,
            "request_digest": request_digest,
            "attempts": [item.model_dump(mode="json") for item in attempts],
        }
    )
    return ModelGatewayFailure(
        failure_id=failure_id,
        error_type=error_type,
        stage=stage,
        message=f"Model gateway failed at {stage} ({error_type})",
        status_code=status_code,
        retryable=retryable,
        request_digest=request_digest,
        logical_call_id=logical_call_id,
        route=route,
        route_profile=route_profile,
        model_id=model_id,
        prompt_version=prompt_version,
        deadline_ms=deadline_ms,
        remaining_budget_ms=remaining_budget_ms,
        fallback_status=fallback_status,
        recovery_kind=recovery_kind,
        recovery_independence=recovery_independence,
        budget_dimension=budget_dimension,
        attempts=attempts,
    )


def record_attempt(
    gateway,
    model_id: str,
    endpoint: str,
    started: float,
    status_code: int | None,
    succeeded: bool,
    retryable: bool,
    error_type: str | None,
    raw_usage: Any,
    *,
    run_id: str | None,
    reservation_id: str | None = None,
    logical_call_id: str | None = None,
    provider_request_sha256: str,
    task_kind: str = ModelTaskKind.GENERAL.value,
    lane: str = "lightweight",
    router_version: str = MODEL_ROUTER_VERSION,
    prompt_version: str,
    prompt_artifact_id: str | None = None,
    prompt_selection_digest: str | None = None,
    prompt_optimizer_attempt_id: str | None = None,
    prompt_lineage_reason: str = "legacy_unbound_prompt",
    parent_logical_call_id: str | None = None,
    lineage_stage: str = "legacy",
    recovery_kind: str = "primary",
    recovery_independence: str = "not_applicable",
    response_sha256: str | None,
    ordinal: int = 0,
    stage: str = "provider",
    deadline_ms: int = 0,
    remaining_budget_ms: int = 0,
    route: str | None = None,
    route_profile: str = PRIMARY_ROUTE_PROFILE,
    estimated_input_tokens: int = 0,
    estimated_output_tokens: int = 0,
    retry_after_ms: int | None = None,
    retry_after_source: Literal["delta_seconds", "http_date"] | None = None,
) -> ProviderAttempt:
    logical_call_id = logical_call_id or f"legacy:{provider_request_sha256}"
    parent_logical_call_id = parent_logical_call_id or logical_call_id
    if task_kind == "embedding" and prompt_lineage_reason == "legacy_unbound_prompt":
        prompt_lineage_reason = "legacy_embedding"
    prompt_selection_digest = prompt_selection_digest or legacy_selection_digest(
        prompt_version=prompt_version,
        task_kind=task_kind,
    )
    usage = raw_usage if isinstance(raw_usage, dict) else {}
    has_input_usage = "prompt_tokens" in usage or "input_tokens" in usage
    has_output_usage = "completion_tokens" in usage or "output_tokens" in usage
    input_tokens, invalid_input = bounded_usage_count(usage.get("prompt_tokens", usage.get("input_tokens", 0)))
    output_tokens, invalid_output = bounded_usage_count(usage.get("completion_tokens", usage.get("output_tokens", 0)))
    cache_hit_input_tokens, invalid_cache_hit = bounded_usage_count(usage.get("prompt_cache_hit_tokens", 0))
    cache_miss_input_tokens, invalid_cache_miss = bounded_usage_count(usage.get("prompt_cache_miss_tokens", 0))
    input_known = isinstance(raw_usage, dict) and has_input_usage and not invalid_input
    output_known = isinstance(raw_usage, dict) and has_output_usage and not invalid_output
    cache_known = not invalid_cache_hit and not invalid_cache_miss
    if cache_hit_input_tokens or cache_miss_input_tokens:
        if cache_hit_input_tokens + cache_miss_input_tokens != input_tokens:
            cache_known = False
            cache_hit_input_tokens = cache_miss_input_tokens = 0
    invalid_usage = not input_known or not output_known or not cache_known
    if invalid_usage:
        # A missing/malformed provider usage object must never release a
        # paid attempt back to zero.  Settle conservatively from the request
        # and response envelopes (or the reserved output budget when a
        # response envelope is incomplete).
        if not input_known:
            input_tokens = max(input_tokens, max(0, estimated_input_tokens))
        if not output_known:
            output_tokens = max(output_tokens, max(0, estimated_output_tokens))
        logger.warning("provider returned invalid usage telemetry; conservative local estimates were settled")
    settled_usage = ModelUsage(
        provider_requests=1,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_hit_input_tokens=cache_hit_input_tokens,
        cache_miss_input_tokens=cache_miss_input_tokens,
        cost_units=gateway._cost_units(model_id, input_tokens, output_tokens),
    )
    provider_input_tokens = input_tokens if input_known else 0
    provider_output_tokens = output_tokens if output_known else 0
    provider_cost = gateway._cost_units(model_id, provider_input_tokens, provider_output_tokens)
    provider_reported_usage = ModelUsage(
        provider_requests=0 if invalid_usage else 1,
        input_tokens=provider_input_tokens,
        output_tokens=provider_output_tokens,
        cache_hit_input_tokens=cache_hit_input_tokens if cache_known else 0,
        cache_miss_input_tokens=cache_miss_input_tokens if cache_known else 0,
        cost_units=provider_cost,
    )
    conservative_reserved_usage = ModelUsage(
        provider_requests=1 if invalid_usage else 0,
        input_tokens=0 if input_known else input_tokens,
        output_tokens=0 if output_known else output_tokens,
        cost_units=max(0.0, settled_usage.cost_units - provider_cost),
    )
    MODEL_REQUESTS.labels(model=model_id, status="success" if succeeded else "failure").inc()
    MODEL_TOKENS.labels(model=model_id, direction="input").inc(input_tokens)
    MODEL_TOKENS.labels(model=model_id, direction="output").inc(output_tokens)
    MODEL_TOKENS.labels(model=model_id, direction="cache_hit_input").inc(cache_hit_input_tokens)
    MODEL_TOKENS.labels(model=model_id, direction="cache_miss_input").inc(cache_miss_input_tokens)
    gateway._provider_sequence += 1
    provider_request_id = str(uuid4())
    duration_ms = int((time.monotonic() - started) * 1000)
    cost_units = settled_usage.cost_units
    provider_attempt = ProviderAttempt(
        provider_request_id=provider_request_id,
        sequence=gateway._provider_sequence,
        model_id=model_id,
        endpoint=endpoint,
        duration_ms=duration_ms,
        status_code=status_code,
        succeeded=succeeded,
        retryable=retryable,
        error_type=error_type,
        usage=settled_usage,
        provider_request_sha256=provider_request_sha256,
        task_kind=task_kind,
        lane=lane,
        router_version=router_version,
        prompt_version=prompt_version,
        response_sha256=response_sha256,
        prompt_artifact_id=prompt_artifact_id,
        prompt_selection_digest=prompt_selection_digest,
        prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
        prompt_lineage_reason=prompt_lineage_reason,
        run_id=run_id,
        logical_call_id=logical_call_id,
        parent_logical_call_id=parent_logical_call_id,
        recovery_kind=recovery_kind,
        recovery_independence=recovery_independence,
        ordinal=ordinal,
        stage=stage,
        lineage_stage=lineage_stage,
        deadline_ms=max(0, deadline_ms),
        remaining_budget_ms=max(0, remaining_budget_ms),
        route=route or gateway._route_name(task_kind, lane),
        route_profile=route_profile,
        retry_after_ms=retry_after_ms,
        retry_after_source=retry_after_source,
        provider_reported_usage=provider_reported_usage,
        conservative_reserved_usage=conservative_reserved_usage,
        unknown_usage=invalid_usage,
    )
    gateway._provider_attempts.append(provider_attempt)
    if gateway._usage_store is not None and run_id is not None and reservation_id is not None:
        try:
            gateway._usage_store.settle_usage(
                seal_contract(
                    UsageSettlement,
                    digest_field="receipt_digest",
                    reservation_id=reservation_id,
                    run_id=run_id,
                    model_invocation_ids=[provider_request_id],
                    provider_requests=1,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_hit_input_tokens=cache_hit_input_tokens,
                    cache_miss_input_tokens=cache_miss_input_tokens,
                    cost_units=cost_units,
                    wall_time_ms=duration_ms,
                )
            )
        except Exception as exc:
            # Accounting is an audit side effect after the provider call.
            # It must never replace a successful paid response, a transport
            # timeout, or task cancellation with an unrelated DB error.  The
            # in-memory ProviderAttempt retains the full actual usage for the
            # coordinator/reconciler to persist and diagnose.
            logger.warning(
                "model usage settlement failed without masking provider outcome: %s",
                type(exc).__name__,
                extra={
                    "run_id": run_id,
                    "provider_request_id": provider_request_id,
                },
            )
    if gateway._attempt_sink is not None and run_id is not None:
        try:
            gateway._attempt_sink(run_id, [provider_attempt])
        except Exception as exc:
            # Keep the in-memory attempt for the checkpoint retry. A sink
            # outage must not turn a completed paid response into another
            # provider call.
            logger.warning(
                "immediate model attempt persistence failed; checkpoint retry retained: %s",
                type(exc).__name__,
                extra={"run_id": run_id, "provider_request_id": provider_request_id},
            )
    return provider_attempt
