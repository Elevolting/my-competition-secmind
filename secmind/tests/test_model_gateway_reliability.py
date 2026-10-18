from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from secmind.coordinator import CoordinatorStore, ModelGatewayFailureRow
from secmind.investigation.store import InvestigationStore
from secmind.llm import ModelGatewayError, ModelGatewayFailure, QwenGateway
from secmind.model_circuit import CircuitPermit
from secmind.model_gateway.recovery_policy import (
    INFRASTRUCTURE_FALLBACK_MAX_PROMPT_BYTES,
    infrastructure_fallback_prompt,
)
from secmind.model_gateway.transport import parse_retry_after
from secmind.model_router import FALLBACK_ROUTE_PROFILE, PRIMARY_ROUTE_PROFILE, ModelTaskKind


class Output(BaseModel):
    answer: str


class DelayedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], delay: float) -> None:
        self.chunks = chunks
        self.delay = delay
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class PartialThenDelayedStream(httpx.AsyncByteStream):
    def __init__(self, first_chunk: bytes, delay: float) -> None:
        self.first_chunk = first_chunk
        self.delay = delay
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.first_chunk
        await asyncio.sleep(self.delay)
        yield b"{}"

    async def aclose(self) -> None:
        self.closed = True


def enable_mock(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"


def test_retry_after_parser_supports_delta_seconds_http_date_and_hard_cap() -> None:
    now = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

    assert parse_retry_after("17", now=now) == (17.0, "delta_seconds")
    assert parse_retry_after("999999999999999999999", now=now) == (300.0, "delta_seconds")
    assert parse_retry_after("Tue, 18 Aug 2026 12:00:09 GMT", now=now) == (9.0, "http_date")
    assert parse_retry_after("Tue, 18 Aug 2026 11:59:59 GMT", now=now) == (0.0, "http_date")
    assert parse_retry_after("not-a-delay", now=now) is None
    assert parse_retry_after("9" * 300, now=now) is None
    assert parse_retry_after("1", now=now, max_seconds=float("inf")) is None


def test_transient_fallback_prompt_is_utf8_bounded_and_deterministic() -> None:
    original = "HEAD:" + ("界" * 100_000) + ":TAIL"

    first = infrastructure_fallback_prompt(original, guidance="http_5xx")
    second = infrastructure_fallback_prompt(original, guidance="http_5xx")

    assert first == second
    assert len(first.encode("utf-8")) <= INFRASTRUCTURE_FALLBACK_MAX_PROMPT_BYTES
    assert first.startswith("HEAD:")
    assert first.endswith(":TAIL")
    assert "bounded-infrastructure-fallback" in first
    assert "original_sha256=" in first
    assert "\ufffd" not in first
    assert infrastructure_fallback_prompt(original, guidance="schema") == original
    assert infrastructure_fallback_prompt("small", guidance="timeout") == "small"


@pytest.mark.asyncio
async def test_large_primary_transient_failure_uses_budgeted_fallback_slice(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.max_input_tokens = 350_000
    settings.max_cost_units = 100.0
    long_prompt = "BEGIN:" + ("x" * 479_000) + ":END"
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(502, json={"error": "temporary upstream failure"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    store = InvestigationStore(settings.database_url)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt=long_prompt,
            output_model=Output,
            prompt_version="large-primary-bounded-fallback-v1",
            run_id="run-large-primary-bounded-fallback",
        )
    finally:
        await client.aclose()
        store.close()

    assert output.answer == "ok"
    assert meta.used_fallback is True
    assert len(requests) == 2
    primary_prompt = requests[0]["messages"][-1]["content"]  # type: ignore[index]
    fallback_prompt = requests[1]["messages"][-1]["content"]  # type: ignore[index]
    assert primary_prompt == long_prompt
    assert isinstance(fallback_prompt, str)
    assert len(fallback_prompt.encode("utf-8")) <= INFRASTRUCTURE_FALLBACK_MAX_PROMPT_BYTES
    assert fallback_prompt.startswith("BEGIN:")
    assert fallback_prompt.endswith(":END")
    assert "bounded-infrastructure-fallback" in fallback_prompt
    assert meta.attempts[-1].error_type is None


@pytest.mark.asyncio
async def test_primary_uses_one_strong_attempt_then_a_distinct_bounded_fallback(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-plus"
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(429, json={"error": "rate limited"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="primary-gateway-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert len(requests) == 2
    assert requests[0]["model"] == requests[1]["model"] == "qwen-plus"
    assert requests[0]["max_tokens"] != requests[1]["max_tokens"]
    assert meta.used_fallback is True
    assert [item.ordinal for item in meta.attempts] == [1, 2]
    assert meta.attempts[0].route_profile == PRIMARY_ROUTE_PROFILE
    assert meta.attempts[-1].route_profile == FALLBACK_ROUTE_PROFILE
    assert meta.attempts[0].error_type == "rate_limit"
    assert meta.attempts[0].status_code == 429
    assert meta.attempts[0].request_digest != meta.attempts[1].request_digest
    # The route/profile label does not create an independent semantic source
    # when both slots use the same model.
    assert meta.recovery_kind == "fallback_non_independent"
    assert meta.recovery_independence == "non_independent"
    assert meta.attempts[-1].recovery_kind == "fallback_non_independent"
    assert meta.attempts[-1].recovery_independence == "non_independent"
    # A successful fallback owns the complete task envelope.  The Primary
    # header/first-byte slot is separately bounded at 300 seconds and must
    # leave the configured 120-second recovery reserve intact.
    assert 539_000 <= meta.deadline_ms <= 540_000
    # The deadline is sampled after the monotonic task envelope is created;
    # Linux CI can legitimately consume a millisecond before it is recorded.
    assert 299_000 <= meta.attempts[0].deadline_ms <= 300_000


@pytest.mark.asyncio
async def test_same_provider_fallback_honors_retry_after_without_real_wait(settings, monkeypatch) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    requests: list[dict[str, object]] = []
    sleeps: list[float] = []

    async def capture_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", capture_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": "rate limited"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="retry-after-fallback-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert len(requests) == 2
    assert sleeps == [1.0]
    assert meta.attempts[0].retry_after_ms == 1_000
    assert meta.attempts[0].retry_after_source == "delta_seconds"
    assert meta.recovery_independence == "non_independent"


@pytest.mark.asyncio
async def test_retry_after_larger_than_remaining_deadline_blocks_fallback(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.model_primary_soft_timeout_seconds = 0.05
    settings.model_task_hard_timeout_seconds = 0.20
    settings.model_recovery_reserve_seconds = 0.05
    settings.model_stream_max_seconds = 0.05
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": "rate limited"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    started = time.monotonic()
    try:
        with pytest.raises(ModelGatewayError) as raised:
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="retry-after-deadline-v1",
            )
    finally:
        await client.aclose()

    assert time.monotonic() - started < 0.5
    assert calls == 1
    failure = raised.value.failure
    assert failure is not None
    assert failure.attempts[0].retry_after_ms == 1_000
    assert failure.attempts[0].unknown_usage is True
    assert failure.attempts[0].provider_reported_usage.provider_requests == 0
    assert failure.attempts[0].conservative_reserved_usage.provider_requests == 1
    assert failure.attempts[-1].budget_dimension == "retry_after"
    route_key = gateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001
    assert gateway._circuit.snapshot(route_key)["open_until"] > time.monotonic()  # noqa: SLF001


@pytest.mark.asyncio
async def test_http_200_truncated_json_is_repaired_locally_once(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="local-json-recovery-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert calls == 1
    assert meta.used_fallback is False


@pytest.mark.asyncio
async def test_http_200_semantic_schema_failure_never_replays_same_provider(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":7}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError) as raised:
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="strict-schema-no-replay-v1",
            )
    finally:
        await client.aclose()

    assert calls == 1
    failure = raised.value.failure
    assert failure is not None
    assert failure.error_type == "schema"
    assert failure.attempts[-1].budget_dimension == "same_provider_schema_retry"


@pytest.mark.asyncio
async def test_primary_edge_timeout_uses_the_bounded_fallback(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(522, json={"error": "edge timeout"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="primary-edge-recovery-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert len(requests) == 2
    assert [request["model"] for request in requests] == ["qwen-plus", "qwen-turbo"]
    assert meta.used_fallback is True
    assert [item.error_type for item in meta.attempts] == ["edge_timeout_522", None]
    assert [item.ordinal for item in meta.attempts] == [1, 2]


@pytest.mark.asyncio
async def test_primary_schema_fallback_repairs_candidate_without_replaying_full_task(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    # Only an actually distinct provider may receive a paid semantic repair.
    settings.fallback_model = "deepseek-v4-flash"
    requests: list[dict[str, object]] = []
    long_task = "sensitive task context " * 20_000
    invalid_candidate = '{"answer": 7}'

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": invalid_candidate}}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"repaired"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt=long_task,
            output_model=Output,
            prompt_version="primary-schema-repair-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "repaired"
    assert meta.used_fallback is True
    assert len(requests) == 2
    assert [request["model"] for request in requests] == ["qwen-plus", "deepseek-v4-flash"]
    fallback_messages = requests[1]["messages"]
    assert isinstance(fallback_messages, list)
    fallback_prompt = fallback_messages[-1]["content"]
    assert isinstance(fallback_prompt, str)
    assert invalid_candidate in fallback_prompt
    assert long_task not in fallback_prompt
    assert "untrusted candidate" in fallback_prompt
    assert meta.attempts[-1].route_profile == FALLBACK_ROUTE_PROFILE
    assert meta.recovery_kind == "syntax_repair"
    assert meta.recovery_independence == "not_applicable"
    assert meta.attempts[-1].recovery_kind == "syntax_repair"


@pytest.mark.asyncio
async def test_primary_failure_keeps_provider_error_and_records_unavailable_fallback(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, json={"error": "invalid request"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError) as raised:
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="primary-gateway-v1",
            )
    finally:
        await client.aclose()

    assert calls == 1
    assert raised.value.failure is not None
    failure = raised.value.failure
    assert failure.error_type == "provider_response"
    assert failure.status_code == 400
    assert failure.fallback_status == "unavailable"
    assert failure.attempts[-1].error_type == "fallback_unavailable"
    assert failure.attempts[-1].stage == "fallback_gate"
    assert failure.attempts[-1].budget_dimension == "fallback_not_eligible"


@pytest.mark.asyncio
async def test_same_provider_fallback_is_diagnosed_as_non_independent(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(429, json={"error": "rate limited"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="primary-semantic-fallback-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert [request["model"] for request in requests] == ["qwen-plus", "qwen-turbo"]
    assert meta.recovery_kind == "semantic_fallback"
    assert meta.recovery_independence == "non_independent"
    assert meta.attempts[-1].recovery_kind == "semantic_fallback"
    assert meta.attempts[-1].recovery_independence == "non_independent"


@pytest.mark.asyncio
async def test_fallback_output_budget_is_clamped_to_actual_remaining_task_time(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-turbo"
    settings.fallback_model = "qwen-turbo"
    settings.model_primary_soft_timeout_seconds = 0.2
    settings.model_task_hard_timeout_seconds = 1.0
    settings.model_recovery_reserve_seconds = 0.2
    settings.model_stream_max_seconds = 0.2
    settings.model_max_output_tokens = 4_000
    settings.model_fallback_max_output_tokens = 2_000
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            # Make the fallback observe less than the full one-second task
            # envelope while keeping the primary failure a deterministic 429.
            time.sleep(0.15)
            return httpx.Response(429, json={"error": "rate limited"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="primary-budget-clamp-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert len(requests) == 2
    fallback_tokens = requests[1]["max_tokens"]
    assert isinstance(fallback_tokens, int)
    assert 128 <= fallback_tokens < settings.model_fallback_max_output_tokens
    assert meta.deadline_ms < 1_000
    assert meta.attempts[-1].deadline_ms == meta.deadline_ms


@pytest.mark.asyncio
async def test_disabled_fallback_exposes_safe_gate_dimension(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.model_primary_fallback_enabled = False

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid request"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError) as raised:
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="primary-disabled-fallback-v1",
            )
    finally:
        await client.aclose()

    failure = raised.value.failure
    assert failure is not None
    fallback = failure.attempts[-1]
    assert fallback.stage == "fallback_gate"
    assert fallback.budget_dimension == "fallback_disabled"


@pytest.mark.asyncio
async def test_primary_read_idle_timeout_uses_the_real_fallback(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.model_read_idle_timeout_seconds = 0.1
    settings.model_timeout_seconds = 1.0
    body = json.dumps({"choices": [{"message": {"content": '{"answer":"ok"}'}}]}).encode()
    slow_stream = DelayedStream([body], delay=0.2)
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, stream=slow_stream)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="primary-gateway-v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert calls == 2
    assert slow_stream.closed
    assert meta.used_fallback is True
    assert meta.attempts[0].stage == "read_idle"
    assert meta.attempts[0].error_type == "timeout"


@pytest.mark.asyncio
async def test_primary_total_deadline_bounds_a_continuous_chunk_stream(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.model_primary_soft_timeout_seconds = 0.05
    settings.model_task_hard_timeout_seconds = 0.50
    settings.model_recovery_reserve_seconds = 0.20
    settings.model_stream_max_seconds = 0.15
    settings.model_read_idle_timeout_seconds = 0.08
    # Every chunk arrives before the idle deadline, but the stream never
    # completes before the logical call deadline. This distinguishes the
    # total budget from a per-chunk timeout.
    slow_stream = DelayedStream([b"{}"] * 30, delay=0.03)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=slow_stream)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError) as raised:
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="primary-gateway-v1",
            )
    finally:
        await client.aclose()

    failure = raised.value.failure
    assert failure is not None
    assert slow_stream.closed
    primary_attempt = next(item for item in failure.attempts if item.route_profile == PRIMARY_ROUTE_PROFILE)
    # Chunks make progress faster than the idle limit, but the independent
    # stream-total deadline still ends the response.  This is deliberately
    # different from the former monolithic task timeout.
    assert primary_attempt.stage == "stream_total"
    assert primary_attempt.error_type == "timeout"
    assert primary_attempt.stage != "read_idle"


@pytest.mark.asyncio
async def test_partial_stream_timeout_settles_reserved_output_budget(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    settings.model_primary_fallback_enabled = False
    settings.model_read_idle_timeout_seconds = 0.02
    partial_stream = PartialThenDelayedStream(b'{"choices":[', delay=0.08)
    run_id = "run-partial-stream-budget"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=partial_stream)

    store = InvestigationStore(settings.database_url)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        with pytest.raises(ModelGatewayError):
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="partial-stream-budget-v1",
                run_id=run_id,
            )
    finally:
        await client.aclose()
        store.close()

    attempt = gateway.provider_attempts_for(run_id)[0]
    assert partial_stream.closed
    assert attempt.error_type == "timeout"
    assert attempt.stage == "read_idle"
    assert attempt.usage.output_tokens == settings.model_max_output_tokens


@pytest.mark.asyncio
async def test_non_primary_retry_wait_is_bounded_by_logical_deadline(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-plus"
    settings.model_timeout_seconds = 0.1
    settings.model_max_attempts = 2
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "temporarily unavailable"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    started = time.monotonic()
    try:
        with pytest.raises(ModelGatewayError):
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PLANNING,
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="planning-deadline-v1",
            )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    assert elapsed < 0.35
    assert 1 <= calls <= 2
    assert len(gateway.provider_attempts) == calls
    assert all(attempt.status_code == 503 for attempt in gateway.provider_attempts)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["rate_limit", "http_5xx", "transport"])
async def test_provider_infrastructure_faults_share_circuit_across_profiles(settings, failure_kind: str) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-plus"
    settings.model_primary_fallback_enabled = False
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure_kind == "transport":
            raise httpx.ConnectError("provider unavailable", request=request)
        status_code = 429 if failure_kind == "rate_limit" else 503
        return httpx.Response(status_code, json={"error": failure_kind})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        for index in range(3):
            with pytest.raises(ModelGatewayError):
                await gateway.structured(
                    role="planner",
                    task_kind=ModelTaskKind.PRIMARY_REVIEW,
                    system_prompt="system",
                    user_prompt=f"user-{index}",
                    output_model=Output,
                    prompt_version=f"shared-circuit-{failure_kind}-v1",
                )
    finally:
        await client.aclose()

    primary_scope = gateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001
    fallback_scope = gateway._route_key("qwen-plus", FALLBACK_ROUTE_PROFILE)  # noqa: SLF001
    assert primary_scope == fallback_scope
    assert calls == 3
    assert gateway._circuit.acquire(fallback_scope) is CircuitPermit.OPEN  # noqa: SLF001


@pytest.mark.asyncio
async def test_schema_failures_do_not_open_shared_provider_scope(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-plus"
    settings.model_primary_fallback_enabled = False
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":7}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        for index in range(4):
            with pytest.raises(ModelGatewayError):
                await gateway.structured(
                    role="planner",
                    task_kind=ModelTaskKind.PRIMARY_REVIEW,
                    system_prompt="system",
                    user_prompt=f"schema-user-{index}",
                    output_model=Output,
                    prompt_version="schema-local-v1",
                )
    finally:
        await client.aclose()

    fallback_scope = gateway._route_key("qwen-plus", FALLBACK_ROUTE_PROFILE)  # noqa: SLF001
    assert calls == 4
    assert gateway._circuit.acquire(fallback_scope) is CircuitPermit.CLOSED  # noqa: SLF001


@pytest.mark.asyncio
async def test_open_primary_circuit_stays_open_across_fallback_runs(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        model_id = json.loads(request.content)["model"]
        calls.append(model_id)
        if model_id == "qwen-plus":
            return httpx.Response(503, json={"error": "primary unavailable"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        for index in range(5):
            output, _ = await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PRIMARY_REVIEW,
                system_prompt="system",
                user_prompt=f"user-{index}",
                output_model=Output,
                prompt_version="circuit-scope-v1",
            )
            assert output.answer == "ok"
    finally:
        await client.aclose()

    # Three provider failures open Primary.  The fourth and fifth runs must
    # continue using the healthy fallback without probing Primary again.
    assert calls.count("qwen-plus") == 3
    assert calls.count("qwen-turbo") == 5
    route_key = gateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001
    assert gateway._circuit.snapshot(route_key)["open_until"] > time.monotonic()  # noqa: SLF001


def test_gateway_failure_and_attempt_diagnostics_are_durable(settings) -> None:
    coordinator = CoordinatorStore(settings.database_url)
    failure = ModelGatewayFailure(
        failure_id="a" * 64,
        logical_call_id="call-1",
        error_type="timeout",
        stage="read_idle",
        message="Model gateway failed at read_idle (timeout)",
        retryable=True,
        route="primary_review:reasoning",
        route_profile=PRIMARY_ROUTE_PROFILE,
        model_id="qwen-plus",
        prompt_version="primary-gateway-v1",
        deadline_ms=180_000,
        remaining_budget_ms=1_000,
        fallback_status="failed",
    )
    try:
        coordinator.record_model_failure("run-1", failure)
        coordinator.record_model_failure("run-1", failure)
        with coordinator.engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM model_gateway_failures")).scalar_one() == 1
        with Session(coordinator.engine) as session:
            row = session.get(ModelGatewayFailureRow, "a" * 64)
            assert row is not None
            assert row.logical_call_id == "call-1"
    finally:
        coordinator.close()
