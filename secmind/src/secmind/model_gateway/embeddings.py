"""Embedding transport and response validation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from secmind.model_gateway.contracts import (
    ModelGatewayError,
    ModelResponseTooLargeError,
    RetryableModelError,
)
from secmind.model_gateway.identity import canonical_sha256
from secmind.model_gateway.transport import read_bounded_response
from secmind.model_router import MODEL_ROUTER_VERSION


async def embeddings(gateway, texts: list[str], *, run_id: str | None = None) -> list[list[float]]:
    """Create embeddings for the Qdrant boundary without exposing provider details upstream."""
    if not texts or any(not text.strip() for text in texts):
        raise ValueError("Embedding input must contain non-empty text")
    if gateway.settings.demo_mode:
        raise ModelGatewayError("Embedding calls are disabled in deterministic demo mode")
    if gateway.policy.embedding.provider != gateway.policy.chat_provider:
        raise ModelGatewayError("Embedding provider does not match the configured chat provider")
    client = gateway._require_provider()
    endpoint_url = f"{gateway.policy.base_url}/embeddings"
    request_payload = {"model": gateway.policy.embedding.model_id, "input": texts}
    provider_request_sha256 = canonical_sha256(
        {
            "endpoint": endpoint_url,
            "payload": request_payload,
        }
    )
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(gateway.settings.model_max_attempts),
        wait=wait_exponential_jitter(initial=0.5, max=8),
        retry=retry_if_exception_type((RetryableModelError, httpx.TransportError)),
        reraise=True,
    ):
        with attempt:
            started = time.monotonic()
            reservation_id = gateway._reserve_provider_attempt(
                run_id,
                gateway.policy.embedding.model_id,
                "embeddings",
                input_bytes=sum(len(item.encode("utf-8")) for item in texts),
                output_tokens=0,
            )
            response: httpx.Response | None = None
            response_bytes: bytes | None = None
            try:
                async with asyncio.timeout(gateway.settings.model_timeout_seconds):
                    async with client.stream(
                        "POST",
                        endpoint_url,
                        headers={"Authorization": f"Bearer {gateway._api_key()}"},
                        timeout=gateway._http_timeout(),
                        json=request_payload,
                    ) as response:
                        if response.status_code < 400:
                            response_bytes = await read_bounded_response(
                                response,
                                max_bytes=gateway.settings.model_max_response_bytes,
                                read_idle_timeout_seconds=gateway.settings.model_read_idle_timeout_seconds,
                            )
            except ModelResponseTooLargeError:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None if response is None else response.status_code,
                    False,
                    False,
                    "response_too_large",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise
            except TimeoutError:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None,
                    False,
                    True,
                    "timeout",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise RetryableModelError("Embedding response deadline exceeded") from None
            except httpx.TimeoutException:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None,
                    False,
                    True,
                    "timeout",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise
            except httpx.TransportError as exc:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None,
                    False,
                    True,
                    type(exc).__name__,
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise
            except asyncio.CancelledError:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None,
                    False,
                    False,
                    "cancelled",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise
            except Exception as exc:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    None,
                    False,
                    False,
                    type(exc).__name__,
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise ModelGatewayError("Embedding transport failed") from exc
            if response is None:  # pragma: no cover - a completed stream always exposes its response
                raise AssertionError("Embedding stream completed without a response")
            if response.status_code in {408, 409, 429} or response.status_code >= 500:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    response.status_code,
                    False,
                    True,
                    "retryable_response",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise RetryableModelError(f"Retryable embedding response: {response.status_code}")
            if response.status_code >= 400:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    response.status_code,
                    False,
                    False,
                    "provider_response",
                    {},
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=None,
                )
                raise ModelGatewayError(f"Embedding response: {response.status_code}")
            if response_bytes is None:  # pragma: no cover - successful responses are always read
                raise AssertionError("Embedding response body was not read")
            raw_usage: Any = {}
            malformed_message = "Malformed embedding response"
            try:
                body = json.loads(response_bytes)
                if not isinstance(body, dict):
                    raise TypeError("embedding response must be a JSON object")
                raw_usage = body.get("usage", {})
                rows = body["data"]
                if not isinstance(rows, list) or len(rows) != len(texts):
                    malformed_message = "Embedding response count does not match input count"
                    raise ValueError(malformed_message)
                indexed_vectors: dict[int, list[float]] = {}
                expected_dimension: int | None = None
                for row in rows:
                    if not isinstance(row, dict):
                        raise TypeError("embedding row must be a JSON object")
                    index = row["index"]
                    if isinstance(index, bool) or not isinstance(index, int):
                        raise TypeError("embedding index must be an integer")
                    if index < 0 or index >= len(texts) or index in indexed_vectors:
                        raise ValueError("embedding response contains a duplicate or out-of-range index")
                    raw_vector = row["embedding"]
                    if not isinstance(raw_vector, list) or not raw_vector:
                        raise TypeError("embedding vector must be a non-empty array")
                    vector = [float(value) for value in raw_vector]
                    if any(not math.isfinite(value) for value in vector):
                        raise ValueError("embedding vector contains a non-finite value")
                    if expected_dimension is None:
                        expected_dimension = len(vector)
                    elif len(vector) != expected_dimension:
                        raise ValueError("embedding response dimensions are inconsistent")
                    indexed_vectors[index] = vector
                vectors = [indexed_vectors[index] for index in range(len(texts))]
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                RecursionError,
                KeyError,
                OverflowError,
                TypeError,
                ValueError,
            ) as exc:
                gateway._record_attempt(
                    gateway.policy.embedding.model_id,
                    "embeddings",
                    started,
                    response.status_code,
                    False,
                    False,
                    "malformed_response",
                    raw_usage,
                    run_id=run_id,
                    reservation_id=reservation_id,
                    provider_request_sha256=provider_request_sha256,
                    task_kind="embedding",
                    lane="embedding",
                    router_version=MODEL_ROUTER_VERSION,
                    prompt_version="embedding-v1",
                    response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                )
                raise ModelGatewayError(malformed_message) from exc
            gateway._record_attempt(
                gateway.policy.embedding.model_id,
                "embeddings",
                started,
                response.status_code,
                True,
                False,
                None,
                raw_usage,
                run_id=run_id,
                reservation_id=reservation_id,
                provider_request_sha256=provider_request_sha256,
                task_kind="embedding",
                lane="embedding",
                router_version=MODEL_ROUTER_VERSION,
                prompt_version="embedding-v1",
                response_sha256=hashlib.sha256(response_bytes).hexdigest(),
            )
            return vectors
    raise AssertionError("Retry loop exited unexpectedly")
