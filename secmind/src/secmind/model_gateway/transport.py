"""HTTP response reading and bounded chat transport retries."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from typing import Any, Literal

import httpx
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from secmind.investigation.store import InvestigationConflict
from secmind.model_gateway.budget import estimate_prompt_tokens
from secmind.model_gateway.contracts import (
    ModelAttemptSummary,
    ModelGatewayError,
    ModelGatewayFailure,
    ModelReadIdleTimeout,
    ModelResponseTooLargeError,
    ProviderAttempt,
    RetryableModelError,
)
from secmind.model_gateway.identity import canonical_sha256
from secmind.model_gateway.provider_gate import (
    ProviderGateTimeout,
    ProviderSlot,
    build_provider_host_gate,
)
from secmind.model_gateway.recovery_policy import (
    parse_retry_after,
    provider_retry_directive,
    retry_after_milliseconds,
)
from secmind.model_router import MODEL_ROUTER_VERSION, PRIMARY_ROUTE_PROFILE, ModelTaskKind


async def read_bounded_response(
    response: httpx.Response,
    *,
    max_bytes: int,
    read_idle_timeout_seconds: float | None = None,
) -> bytes:
    """Read a response with a byte ceiling and a per-chunk idle deadline."""

    for header_value in response.headers.get_list("content-length"):
        for candidate in header_value.split(","):
            try:
                content_length = int(candidate.strip())
            except ValueError:
                continue
            if content_length > max_bytes:
                await response.aclose()
                raise ModelResponseTooLargeError(max_bytes, content_length=content_length)

    content = bytearray()
    iterator = response.aiter_bytes().__aiter__()
    while True:
        try:
            if read_idle_timeout_seconds is None:
                chunk = await iterator.__anext__()
            else:
                async with asyncio.timeout(read_idle_timeout_seconds):
                    chunk = await iterator.__anext__()
        except StopAsyncIteration:
            break
        except TimeoutError as exc:
            await response.aclose()
            raise ModelReadIdleTimeout("provider response read idle deadline exceeded") from exc
        if len(content) + len(chunk) > max_bytes:
            await response.aclose()
            raise ModelResponseTooLargeError(max_bytes)
        content.extend(chunk)
    return bytes(content)


async def request_with_retry(
    gateway,
    model_id: str,
    system_prompt: str,
    user_prompt: str,
    schema: dict[str, Any],
    *,
    run_id: str | None,
    logical_call_id: str | None = None,
    payload: dict[str, Any] | None = None,
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
    deadline_at: float | None = None,
    stream_deadline_at: float | None = None,
    deadline_ms: int = 0,
    attempt_limit: int | None = None,
    attempt_ordinal: int = 1,
    route: str | None = None,
    route_profile: str = PRIMARY_ROUTE_PROFILE,
    normalize_errors: bool = False,
) -> tuple[str, int, ProviderAttempt]:
    """Make one bounded provider slot under a shared logical deadline."""

    started = time.monotonic()
    client = gateway._require_provider()
    request_payload = payload or gateway._chat_payload(
        model_id,
        system_prompt,
        user_prompt,
        schema,
        route_profile=route_profile,
        task_kind=task_kind,
    )
    provider_request_sha256 = canonical_sha256(
        {
            "endpoint": f"{gateway.policy.base_url}/chat/completions",
            "payload": request_payload,
        }
    )
    logical_deadline = deadline_at if deadline_at is not None else started + gateway.settings.model_timeout_seconds
    body_deadline = stream_deadline_at if stream_deadline_at is not None else logical_deadline
    logical_deadline_ms = deadline_ms or max(0, int(gateway.settings.model_timeout_seconds * 1000))
    retry_limit = max(1, int(attempt_limit or gateway.settings.model_max_attempts))
    route_name = route or gateway._route_name(task_kind, lane)
    estimated_input_tokens = estimate_prompt_tokens(
        len(system_prompt.encode("utf-8"))
        + len(user_prompt.encode("utf-8"))
        + len(json.dumps(schema, sort_keys=True).encode("utf-8"))
    )

    def remaining_budget_ms() -> int:
        return max(0, int((logical_deadline - time.monotonic()) * 1000))

    exponential_wait = wait_exponential_jitter(initial=0.5, max=8)

    def bounded_retry_wait(retry_state: RetryCallState) -> float:
        """Keep Tenacity backoff inside the logical model-call deadline."""

        requested = float(exponential_wait(retry_state))
        outcome = retry_state.outcome
        retry_error = outcome.exception() if outcome is not None and outcome.failed else None
        if isinstance(retry_error, RetryableModelError) and retry_error.retry_after_seconds is not None:
            requested = max(requested, retry_error.retry_after_seconds)
        remaining_seconds = max(0.0, logical_deadline - time.monotonic())
        return min(requested, remaining_seconds)

    # Incomplete provider envelopes retain reserved output instead of settling to zero.
    reserved_output_tokens = max(
        0,
        int(request_payload.get("max_tokens", gateway._max_output_tokens(route_profile))),
    )

    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(retry_limit),
        wait=bounded_retry_wait,
        retry=retry_if_exception_type((RetryableModelError, httpx.TransportError)),
        reraise=True,
    ):
        with attempt:
            ordinal = attempt_ordinal + attempt.retry_state.attempt_number - 1
            # Do not reserve or record a physical provider attempt when the
            # bounded retry wait has left too little time to enter transport.
            if remaining_budget_ms() < 10:
                raise RetryableModelError("Model response deadline exceeded") from None
            request_started = time.monotonic()
            provider_slot: ProviderSlot | None = None
            try:
                provider_slot = await build_provider_host_gate(gateway, model_id=model_id).acquire(
                    deadline_at=logical_deadline,
                    request_digest=f"{provider_request_sha256}:{logical_call_id or ''}:{ordinal}",
                )
            except ProviderGateTimeout:
                raise RetryableModelError("Model provider concurrency deadline exceeded") from None
            try:
                reservation_id = gateway._reserve_provider_attempt(
                    run_id,
                    model_id,
                    "chat",
                    input_bytes=len(system_prompt.encode("utf-8"))
                    + len(user_prompt.encode("utf-8"))
                    + len(json.dumps(schema, sort_keys=True).encode("utf-8")),
                    output_tokens=reserved_output_tokens,
                )
            except InvestigationConflict as exc:
                conflict_text = str(exc).casefold()
                dimension = next(
                    (
                        name
                        for name in (
                            "input_tokens",
                            "output_tokens",
                            "provider_requests",
                            "cost_units",
                            "tool_calls",
                            "artifact_bytes",
                        )
                        if name in conflict_text
                    ),
                    (
                        "reservation_identity"
                        if "reused with different content" in conflict_text
                        else "reservation_parent"
                        if "parent is missing" in conflict_text
                        else "usage"
                    ),
                )
                budget_summary = ModelAttemptSummary(
                    ordinal=ordinal,
                    stage="budget_reservation",
                    error_type="budget_conflict",
                    retryable=False,
                    request_digest=provider_request_sha256,
                    route=route_name,
                    route_profile=route_profile,
                    model_id=model_id,
                    prompt_version=prompt_version,
                    prompt_artifact_id=prompt_artifact_id,
                    prompt_selection_digest=prompt_selection_digest,
                    prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                    prompt_lineage_reason=prompt_lineage_reason,
                    parent_logical_call_id=parent_logical_call_id,
                    lineage_stage=lineage_stage,
                    recovery_kind=recovery_kind,
                    recovery_independence=recovery_independence,
                    deadline_ms=logical_deadline_ms,
                    remaining_budget_ms=remaining_budget_ms(),
                    logical_call_id=logical_call_id,
                    budget_dimension=dimension,
                )
                failure_id = canonical_sha256(
                    {
                        "logical_call_id": logical_call_id,
                        "stage": budget_summary.stage,
                        "error_type": budget_summary.error_type,
                        "dimension": dimension,
                        "request_digest": provider_request_sha256,
                    }
                )
                if provider_slot is not None:
                    provider_slot.release()
                raise ModelGatewayError(
                    f"Model usage reservation exceeded the {dimension} budget",
                    failure=ModelGatewayFailure(
                        failure_id=failure_id,
                        error_type="budget_conflict",
                        stage="budget_reservation",
                        message=f"Model usage reservation exceeded the {dimension} budget",
                        retryable=False,
                        request_digest=provider_request_sha256,
                        logical_call_id=logical_call_id,
                        route=route_name,
                        route_profile=route_profile,
                        model_id=model_id,
                        prompt_version=prompt_version,
                        deadline_ms=logical_deadline_ms,
                        remaining_budget_ms=remaining_budget_ms(),
                        fallback_status="not_eligible",
                        budget_dimension=dimension,
                        attempts=[budget_summary],
                    ),
                ) from exc
            except BaseException:
                if provider_slot is not None:
                    provider_slot.release()
                raise
            response: httpx.Response | None = None
            response_bytes: bytes | None = None

            def record_attempt(
                status_code: int | None,
                succeeded: bool,
                retryable: bool,
                error_type: str | None,
                raw_usage: Any,
                *,
                stage: str,
                response_sha256: str | None = None,
                response_output_bytes: int = 0,
                conservative_output_tokens: int | None = None,
                retry_after_ms: int | None = None,
                retry_after_source: Literal["delta_seconds", "http_date"] | None = None,
                request_started_value: float = request_started,
                reservation_id_value: str | None = reservation_id,
                ordinal_value: int = ordinal,
            ) -> ProviderAttempt:
                return gateway._record_attempt(
                    model_id,
                    "chat",
                    request_started_value,
                    status_code,
                    succeeded,
                    retryable,
                    error_type,
                    raw_usage,
                    run_id=run_id,
                    reservation_id=reservation_id_value,
                    logical_call_id=logical_call_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind=task_kind,
                    lane=lane,
                    router_version=router_version,
                    prompt_version=prompt_version,
                    prompt_artifact_id=prompt_artifact_id,
                    prompt_selection_digest=prompt_selection_digest,
                    prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                    prompt_lineage_reason=prompt_lineage_reason,
                    parent_logical_call_id=parent_logical_call_id,
                    lineage_stage=lineage_stage,
                    recovery_kind=recovery_kind,
                    recovery_independence=recovery_independence,
                    response_sha256=response_sha256,
                    ordinal=ordinal_value,
                    stage=stage,
                    deadline_ms=logical_deadline_ms,
                    remaining_budget_ms=remaining_budget_ms(),
                    route=route_name,
                    route_profile=route_profile,
                    estimated_input_tokens=estimated_input_tokens,
                    estimated_output_tokens=max(
                        max(0, math.ceil(response_output_bytes / 2)),
                        reserved_output_tokens
                        if conservative_output_tokens is None
                        else max(0, conservative_output_tokens),
                    ),
                    retry_after_ms=retry_after_ms,
                    retry_after_source=retry_after_source,
                )

            stream_context: Any | None = None
            try:
                remaining_ms = remaining_budget_ms()
                if remaining_ms <= 0:
                    raise TimeoutError("Model response deadline exceeded")
                stream_context = client.stream(
                    "POST",
                    f"{gateway.policy.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {gateway._api_key()}"},
                    timeout=gateway._http_timeout(),
                    json=request_payload,
                )
                # The soft deadline bounds connection and first byte. Once
                # headers arrive, body progress is governed by read-idle,
                # stream-max and the task hard envelope rather than the
                # former monolithic 180 second timer.
                async with asyncio.timeout(max(0.001, remaining_ms / 1000)):
                    response = await stream_context.__aenter__()
                if response.status_code < 400:
                    body_remaining = min(
                        max(0.0, body_deadline - time.monotonic()),
                        gateway.settings.model_stream_max_seconds,
                    )
                    if body_remaining <= 0:
                        raise TimeoutError("Model response stream deadline exceeded")
                    async with asyncio.timeout(max(0.001, body_remaining)):
                        response_bytes = await read_bounded_response(
                            response,
                            max_bytes=gateway.settings.model_max_response_bytes,
                            read_idle_timeout_seconds=gateway.settings.model_read_idle_timeout_seconds,
                        )
            except ModelResponseTooLargeError:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    False,
                    "response_too_large",
                    {},
                    stage="response_body",
                    conservative_output_tokens=reserved_output_tokens,
                )
                raise
            except ModelReadIdleTimeout:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    True,
                    "timeout",
                    {},
                    stage="read_idle",
                    conservative_output_tokens=reserved_output_tokens,
                )
                raise RetryableModelError("Model response read idle deadline exceeded") from None
            except TimeoutError:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    True,
                    "timeout",
                    {},
                    stage="first_byte" if response is None else "stream_total",
                    conservative_output_tokens=reserved_output_tokens,
                )
                raise RetryableModelError("Model response deadline exceeded") from None
            except httpx.TimeoutException as exc:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    True,
                    "timeout",
                    {},
                    stage=gateway._timeout_stage(exc),
                    conservative_output_tokens=reserved_output_tokens,
                )
                if normalize_errors:
                    raise RetryableModelError("Model provider timeout") from None
                raise
            except httpx.TransportError as exc:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    True,
                    "transport" if normalize_errors else type(exc).__name__,
                    {},
                    stage="transport",
                    conservative_output_tokens=reserved_output_tokens,
                )
                if normalize_errors:
                    raise RetryableModelError("Model provider transport failed") from None
                raise
            except asyncio.CancelledError:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    False,
                    "cancelled",
                    {},
                    stage="transport",
                    conservative_output_tokens=reserved_output_tokens,
                )
                raise
            except Exception as exc:
                record_attempt(
                    None if response is None else response.status_code,
                    False,
                    False,
                    type(exc).__name__,
                    {},
                    stage="transport",
                    conservative_output_tokens=reserved_output_tokens,
                )
                raise ModelGatewayError("Model transport failed") from exc
            finally:
                if stream_context is not None and response is not None:
                    await stream_context.__aexit__(None, None, None)
                if provider_slot is not None:
                    provider_slot.release()

            if response is None:  # pragma: no cover - a completed stream exposes its response
                raise AssertionError("Model stream completed without a response")
            retry_directive = provider_retry_directive(response.status_code, response.headers.get("retry-after"))
            if retry_directive is not None:
                record_attempt(
                    response.status_code,
                    False,
                    True,
                    retry_directive.error_type if normalize_errors else "retryable_response",
                    {},
                    stage="provider_response",
                    retry_after_ms=retry_after_milliseconds(retry_directive),
                    retry_after_source=retry_directive.retry_after_source,
                )
                raise RetryableModelError(
                    f"Retryable model response: {response.status_code}",
                    retry_after_seconds=retry_directive.retry_after_seconds,
                    retry_after_source=retry_directive.retry_after_source,
                )
            if response.status_code >= 400:
                record_attempt(
                    response.status_code,
                    False,
                    False,
                    "provider_response",
                    {},
                    stage="provider_response",
                )
                raise ModelGatewayError(f"Model response: {response.status_code}")
            if response_bytes is None:  # pragma: no cover - successful responses are read
                raise AssertionError("Model response body was not read")

            raw_usage: Any = {}
            try:
                body = json.loads(response_bytes)
                if not isinstance(body, dict):
                    raise TypeError("model response must be a JSON object")
                raw_usage = body.get("usage", {})
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise TypeError("model response content must be a string")
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                RecursionError,
                KeyError,
                IndexError,
                TypeError,
            ) as exc:
                record_attempt(
                    response.status_code,
                    False,
                    False,
                    "parse" if normalize_errors else "malformed_response",
                    raw_usage,
                    stage="response_decode",
                    response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                    response_output_bytes=len(response_bytes),
                )
                raise ModelGatewayError("Malformed model response") from exc

            provider_attempt = record_attempt(
                response.status_code,
                True,
                False,
                None,
                raw_usage,
                stage="provider_response",
                response_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                response_output_bytes=len(content.encode("utf-8")),
            )
            return content, int((time.monotonic() - started) * 1000), provider_attempt
    raise AssertionError("Retry loop exited unexpectedly")


__all__ = ["parse_retry_after", "read_bounded_response", "request_with_retry"]
