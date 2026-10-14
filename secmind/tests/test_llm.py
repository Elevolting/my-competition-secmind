from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.investigation.store import InvestigationStore, UsageReservationRow, UsageSettlementRow
from secmind.llm import (
    DurableReceiptError,
    ModelGatewayError,
    ModelResponseTooLargeError,
    ProviderAttempt,
    QwenGateway,
)
from secmind.prompting import PromptCompiler, PromptContext, PromptRole
from secmind.schemas import DataView


class Output(BaseModel):
    answer: str


def enable_mock(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"


def enable_single_model_mock(settings) -> None:
    enable_mock(settings)
    settings.planner_model = settings.worker_model
    settings.fallback_model = settings.worker_model


class TrackingAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.chunks_yielded = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.chunks_yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def successful_provider_response(endpoint: str) -> bytes:
    if endpoint == "chat":
        body = {"choices": [{"message": {"content": json.dumps({"answer": "ok"})}}]}
    else:
        body = {"data": [{"index": 0, "embedding": [1, 0]}]}
    return json.dumps(body, separators=(",", ":")).encode()


async def call_gateway(gateway: QwenGateway, endpoint: str, *, run_id: str | None = None) -> object:
    if endpoint == "chat":
        output, _ = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
            run_id=run_id,
        )
        return output.answer
    return await gateway.embeddings(["text"], run_id=run_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["chat", "embeddings"])
async def test_gateway_rejects_oversized_content_length_without_reading(settings, endpoint: str) -> None:
    enable_single_model_mock(settings)
    settings.model_max_response_bytes = 64
    streams: list[TrackingAsyncStream] = []
    run_id = f"run-content-length-{endpoint}"

    def handler(_: httpx.Request) -> httpx.Response:
        stream = TrackingAsyncStream([successful_provider_response(endpoint)])
        streams.append(stream)
        return httpx.Response(200, headers={"Content-Length": "65"}, stream=stream)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = InvestigationStore(settings.database_url)
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        expected_error = ModelGatewayError if endpoint == "chat" else ModelResponseTooLargeError
        with pytest.raises(expected_error, match="byte limit"):
            await call_gateway(gateway, endpoint, run_id=run_id)

        assert len(gateway.provider_attempts) == 1
        assert store.settled_provider_usage(run_id).provider_requests == 1
        assert store.unsettled_reservation_ids(run_id) == []
    finally:
        await client.aclose()
        store.close()

    assert len(streams) == 1
    assert streams[0].chunks_yielded == 0
    assert streams[0].closed
    assert gateway.provider_attempts[0].error_type == "response_too_large"
    assert not gateway.provider_attempts[0].succeeded


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["chat", "embeddings"])
async def test_gateway_stops_and_closes_on_chunked_response_overflow(settings, endpoint: str) -> None:
    enable_single_model_mock(settings)
    settings.model_max_response_bytes = 64
    stream = TrackingAsyncStream([b"x" * 64, b"x", b"unread"])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        expected_error = ModelGatewayError if endpoint == "chat" else ModelResponseTooLargeError
        with pytest.raises(expected_error, match="byte limit"):
            await call_gateway(gateway, endpoint)
    finally:
        await client.aclose()

    assert stream.chunks_yielded == 2
    assert stream.closed
    assert len(gateway.provider_attempts) == 1
    assert gateway.provider_attempts[0].error_type == "response_too_large"
    assert not gateway.provider_attempts[0].succeeded


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["chat", "embeddings"])
async def test_gateway_accepts_response_at_exact_byte_boundary(settings, endpoint: str) -> None:
    enable_single_model_mock(settings)
    response_bytes = successful_provider_response(endpoint)
    settings.model_max_response_bytes = len(response_bytes)
    midpoint = len(response_bytes) // 2
    stream = TrackingAsyncStream([response_bytes[:midpoint], response_bytes[midpoint:]])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(len(response_bytes))},
            stream=stream,
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        result = await call_gateway(gateway, endpoint)
    finally:
        await client.aclose()

    assert result == ("ok" if endpoint == "chat" else [[1.0, 0.0]])
    assert stream.chunks_yielded == 2
    assert stream.closed
    assert len(gateway.provider_attempts) == 1
    assert gateway.provider_attempts[0].succeeded


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["chat", "embeddings"])
async def test_gateway_records_malformed_streamed_json_once(settings, endpoint: str) -> None:
    enable_single_model_mock(settings)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError, match="Malformed|All configured models failed"):
            await call_gateway(gateway, endpoint)
    finally:
        await client.aclose()

    assert len(gateway.provider_attempts) == 1
    assert gateway.provider_attempts[0].error_type == "malformed_response"
    assert not gateway.provider_attempts[0].succeeded


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["chat", "embeddings"])
async def test_gateway_streaming_preserves_retry_attempt_accounting(settings, endpoint: str) -> None:
    enable_single_model_mock(settings)
    settings.model_max_attempts = 2
    settings.model_max_response_bytes = 256
    retry_stream = TrackingAsyncStream([b"x" * 257])
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Content-Length": "257"}, stream=retry_stream)
        response_bytes = successful_provider_response(endpoint)
        return httpx.Response(200, content=response_bytes)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        result = await call_gateway(gateway, endpoint)
    finally:
        await client.aclose()

    assert result == ("ok" if endpoint == "chat" else [[1.0, 0.0]])
    assert calls == 2
    assert retry_stream.chunks_yielded == 0
    assert retry_stream.closed
    assert [attempt.status_code for attempt in gateway.provider_attempts] == [429, 200]
    assert [attempt.succeeded for attempt in gateway.provider_attempts] == [False, True]
    assert [attempt.retryable for attempt in gateway.provider_attempts] == [True, False]


@pytest.mark.asyncio
async def test_fixed_prompt_artifact_preserves_provider_bytes_and_request_hash(settings) -> None:
    enable_mock(settings)
    payloads: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payloads.append(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "ok"})}}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
            },
        )

    context = PromptContext.create(
        run_id="run-byte-equivalent",
        role=PromptRole.PRIMARY,
        phase="canonical_primary",
        languages=("python",),
        trusted_feature_digest="a" * 64,
        scope_digest="b" * 64,
        output_schema_ref="secmind://prompt-schemas/tests.Output",
    )
    artifact = PromptCompiler().compile_fixed(
        context=context,
        output_model=Output,
        system_prompt="system",
        prompt_version="v1",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        _, plain_meta = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
            run_id="run-byte-equivalent",
        )
        _, artifact_meta = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
            run_id="run-byte-equivalent",
            prompt_artifact=artifact,
        )
    finally:
        await client.aclose()

    assert payloads[0] == payloads[1]
    assert plain_meta.request_sha256 == artifact_meta.request_sha256
    assert artifact_meta.prompt_artifact_id == artifact.artifact_id


@pytest.mark.asyncio
async def test_durable_structured_call_reuses_raw_receipt_after_parse_crash(
    settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enable_mock(settings)
    run_id = "run-durable-primary"
    provider_calls = 0

    def paid_response(_: httpx.Request) -> httpx.Response:
        nonlocal provider_calls
        provider_calls += 1
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "restricted-value"})}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
            },
        )

    class SimulatedProcessCrash(BaseException):
        pass

    store = InvestigationStore(settings.database_url)
    artifact_store = ContentAddressedArtifactStore(settings.artifact_root)
    first_client = httpx.AsyncClient(transport=httpx.MockTransport(paid_response))
    first_gateway = QwenGateway(
        settings,
        first_client,
        usage_store=store,
        artifact_store=artifact_store,
    )

    def crash_after_receipt(_raw: str, _output_model: type[BaseModel]) -> BaseModel:
        raise SimulatedProcessCrash

    monkeypatch.setattr(first_gateway, "_parse_model", crash_after_receipt)
    try:
        with pytest.raises(SimulatedProcessCrash):
            await first_gateway.structured(
                role="planner",
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="v1",
                run_id=run_id,
                durable_call_key="canonical-primary:test-fixture",
            )
    finally:
        await first_client.aclose()

    receipts = store.list_objects(run_id, "model.raw_response_receipt.v1")
    assert provider_calls == 1
    assert len(receipts) == 1
    assert receipts[0]["schema_version"] == "1.1"

    def forbid_second_sample(_: httpx.Request) -> httpx.Response:
        raise AssertionError("a durable provider response must be replayed, not sampled again")

    second_client = httpx.AsyncClient(transport=httpx.MockTransport(forbid_second_sample))
    second_gateway = QwenGateway(
        settings,
        second_client,
        usage_store=store,
        artifact_store=artifact_store,
    )
    try:
        output, replay_meta = await second_gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
            run_id=run_id,
            durable_call_key="canonical-primary:test-fixture",
        )
    finally:
        await second_client.aclose()

    assert output.answer == "restricted-value"
    assert provider_calls == 1
    assert replay_meta.replayed_from_receipt is True
    assert replay_meta.usage.provider_requests == 1
    assert replay_meta.usage.total_tokens == 10
    assert replay_meta.provider_reported_usage == replay_meta.usage
    assert replay_meta.conservative_reserved_usage.provider_requests == 0
    assert replay_meta.unknown_usage_attempts == 0
    assert replay_meta.raw_response_artifact_id == replay_meta.response_sha256
    metadata = artifact_store.metadata_for(replay_meta.raw_response_artifact_id)
    assert metadata.data_view == DataView.RAW_RESTRICTED
    assert metadata.run_ids == (run_id,)
    assert artifact_store.read(replay_meta.raw_response_artifact_id) == b'{"answer": "restricted-value"}'

    artifact_store.path_for(replay_meta.raw_response_artifact_id).unlink()
    third_client = httpx.AsyncClient(transport=httpx.MockTransport(forbid_second_sample))
    third_gateway = QwenGateway(
        settings,
        third_client,
        usage_store=store,
        artifact_store=artifact_store,
    )
    try:
        with pytest.raises(DurableReceiptError, match="missing or corrupt"):
            await third_gateway.structured(
                role="planner",
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="v1",
                run_id=run_id,
                durable_call_key="canonical-primary:test-fixture",
            )
    finally:
        await third_client.aclose()
        store.close()

    assert provider_calls == 1


@pytest.mark.asyncio
async def test_gateway_retries_retryable_response_and_records_usage(settings) -> None:
    enable_mock(settings)
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(429, json={"error": "limited"})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "ok"})}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
        run_id="run-model-attempts",
    )
    await client.aclose()
    assert output.answer == "ok"
    assert meta.model_id == settings.planner_model
    assert calls == 3
    assert meta.usage.provider_requests == 3
    assert meta.usage.total_tokens > 10
    assert [attempt.status_code for attempt in gateway.provider_attempts] == [429, 429, 200]
    assert gateway.provider_attempts_for("run-model-attempts") == gateway.provider_attempts
    assert gateway.provider_attempts_for("another-run") == ()
    assert len(gateway.drain_provider_attempts()) == 3
    assert gateway.provider_attempts == ()


@pytest.mark.asyncio
async def test_gateway_records_and_settles_deepseek_cache_usage(settings) -> None:
    enable_mock(settings)
    run_id = "run-cache-telemetry"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "ok"})}}],
                "usage": {
                    "prompt_tokens": 128,
                    "completion_tokens": 3,
                    "total_tokens": 131,
                    "prompt_cache_hit_tokens": 96,
                    "prompt_cache_miss_tokens": 32,
                },
            },
        )

    store = InvestigationStore(settings.database_url)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        _, meta = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="cache-v1",
            run_id=run_id,
        )
        settled = store.settled_provider_usage(run_id)
    finally:
        await client.aclose()
        store.close()

    assert meta.usage.cache_hit_input_tokens == settled.cache_hit_input_tokens == 96
    assert meta.usage.cache_miss_input_tokens == settled.cache_miss_input_tokens == 32
    assert meta.usage.cache_hit_rate == pytest.approx(0.75)


@pytest.mark.asyncio
async def test_connect_errors_settle_every_provider_reservation_and_bound_chat_output(settings) -> None:
    enable_mock(settings)
    run_id = "run-connect-error-usage"
    payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payloads.append(json.loads(request.content))
        raise httpx.ConnectError("mock provider unavailable", request=request)

    store = InvestigationStore(settings.database_url)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        with pytest.raises((httpx.ConnectError, ModelGatewayError)):
            await gateway.structured(
                role="planner",
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="v1",
                run_id=run_id,
            )

        attempts = gateway.provider_attempts_for(run_id)
        assert payloads
        assert len(attempts) == len(payloads)
        assert payloads[0]["max_tokens"] == 16_000
        assert all(payload["max_tokens"] in {12_000, 16_000} for payload in payloads)
        assert all(attempt.error_type == "ConnectError" and attempt.retryable for attempt in attempts)
        assert settings.model_mode == "mock"
        assert settings.max_model_tier == 5.4

        with Session(store.engine) as session:
            reservations = list(
                session.scalars(
                    select(UsageReservationRow).where(
                        UsageReservationRow.run_id == run_id,
                        UsageReservationRow.kind == "model",
                    )
                )
            )
            settlements = list(session.scalars(select(UsageSettlementRow).where(UsageSettlementRow.run_id == run_id)))
        assert len(reservations) == len(attempts)
        assert len(settlements) == len(attempts)
        assert all(reservation.status == "settled" for reservation in reservations)
        assert store.unsettled_reservation_ids(run_id) == []
    finally:
        await client.aclose()
        store.close()


@pytest.mark.asyncio
async def test_offline_mode_never_touches_injected_transport(settings) -> None:
    settings.demo_mode = False
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("offline mode attempted HTTP")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    with pytest.raises(ModelGatewayError, match="offline mode"):
        await gateway.structured(
            role="worker",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    assert calls == 0
    await client.aclose()


def test_mock_mode_requires_injected_client(settings) -> None:
    enable_mock(settings)
    with pytest.raises(ModelGatewayError, match="injected HTTP client"):
        QwenGateway(settings)


@pytest.mark.asyncio
async def test_mock_mode_rejects_network_transport(settings) -> None:
    enable_mock(settings)
    client = httpx.AsyncClient()
    try:
        with pytest.raises(ModelGatewayError, match="MockTransport"):
            QwenGateway(settings, client)
    finally:
        await client.aclose()


def test_live_mode_requires_explicit_switch_credentials_and_trusted_https(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "live"
    with pytest.raises(ModelGatewayError, match="allow_live_models"):
        QwenGateway(settings)
    settings.allow_live_models = True
    with pytest.raises(ModelGatewayError, match="QWEN_API_KEY"):
        QwenGateway(settings)
    settings.qwen_api_key = "test-key"
    settings.qwen_base_url = "https://untrusted.example/v1"
    with pytest.raises(ModelGatewayError, match="not in trusted"):
        QwenGateway(settings)
    settings.trusted_model_base_urls = "http://models.example/v1"
    settings.qwen_base_url = "http://models.example/v1"
    with pytest.raises(ModelGatewayError, match="must use HTTPS"):
        QwenGateway(settings)


def test_live_mode_rejects_cross_provider_chat_routes_and_provider_url_mismatch(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "live"
    settings.allow_live_models = True
    settings.qwen_api_key = "test-key"
    settings.planner_model = "deepseek-v4-flash"
    settings.worker_model = "deepseek-v4-flash"
    settings.fallback_model = "qwen-turbo"
    settings.qwen_base_url = "https://api.deepseek.com"
    settings.trusted_model_base_urls = "https://api.deepseek.com"
    with pytest.raises(ModelGatewayError, match="must use one provider"):
        QwenGateway(settings)

    settings.fallback_model = "deepseek-v4-flash"
    settings.qwen_base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    settings.trusted_model_base_urls = settings.qwen_base_url
    with pytest.raises(ModelGatewayError, match="do not match"):
        QwenGateway(settings)


def test_model_api_key_is_masked_in_settings_representations(settings) -> None:
    sentinel = "sentinel-model-api-key"
    settings.qwen_api_key = sentinel

    assert settings.model_api_key_value() == sentinel
    assert sentinel not in repr(settings)
    assert sentinel not in str(settings)
    assert sentinel not in settings.model_dump_json()


def test_deepseek_key_never_falls_back_to_qwen_secret(settings) -> None:
    settings.qwen_api_key = "legacy-bridge-secret"
    assert settings.model_api_key_value("deepseek") == ""

    settings.deepseek_api_key = "provider-specific-secret"
    assert settings.model_api_key_value("deepseek") == "provider-specific-secret"


@pytest.mark.asyncio
async def test_deepseek_request_uses_official_host_model_and_provider_specific_secret(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"
    settings.model_base_url_provider = "deepseek"
    settings.qwen_base_url = "https://api.deepseek.com"
    settings.trusted_model_base_urls = "https://api.deepseek.com"
    settings.planner_model = "deepseek-v4-flash"
    settings.worker_model = "deepseek-v4-flash"
    settings.fallback_model = "deepseek-v4-flash"
    settings.deepseek_api_key = "deepseek-request-secret"
    settings.qwen_api_key = "qwen-must-not-be-used"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, _ = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert len(requests) == 1
    assert requests[0].url.host == "api.deepseek.com"
    payload = json.loads(requests[0].content)
    assert payload["model"] == "deepseek-v4-flash"
    assert payload["thinking"] == {"type": "enabled"}
    assert payload["reasoning_effort"] == "high"
    assert payload["response_format"] == {"type": "json_object"}
    assert requests[0].headers["Authorization"] == "Bearer deepseek-request-secret"
    assert b"qwen-must-not-be-used" not in requests[0].content
    assert "provider-specific-secret" not in repr(settings)
    assert "provider-specific-secret" not in settings.model_dump_json()


def test_luna_supports_explicit_trusted_openai_compatible_gateway(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "live"
    settings.allow_live_models = True
    settings.planner_model = "gpt-5.6-luna"
    settings.worker_model = "gpt-5.6-luna"
    settings.fallback_model = "gpt-5.6-luna"
    settings.qwen_base_url = "https://gateway.example/v1"
    settings.trusted_model_base_urls = settings.qwen_base_url
    settings.model_base_url_provider = "openai-compatible"
    settings.openai_api_key = "provider-specific-secret"

    gateway = QwenGateway(settings)

    assert gateway.policy.base_url == "https://gateway.example/v1"
    assert gateway.policy.chat_provider == "openai-compatible"
    assert gateway.policy.planner.model_id == "gpt-5.6-luna"
    assert settings.model_api_key_value("openai-compatible") == "provider-specific-secret"


def test_terra_supports_explicit_trusted_openai_compatible_gateway(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "live"
    settings.allow_live_models = True
    settings.planner_model = "gpt-5.6-terra"
    settings.worker_model = "gpt-5.6-terra"
    settings.fallback_model = "gpt-5.6-terra"
    settings.qwen_base_url = "https://gateway.example/v1"
    settings.trusted_model_base_urls = settings.qwen_base_url
    settings.model_base_url_provider = "openai-compatible"
    settings.openai_api_key = "provider-specific-secret"

    gateway = QwenGateway(settings)

    assert gateway.policy.chat_provider == "openai-compatible"
    assert gateway.policy.planner.model_id == "gpt-5.6-terra"


@pytest.mark.asyncio
async def test_embedding_cross_provider_is_rejected_before_transport(settings) -> None:
    enable_mock(settings)
    settings.planner_model = "deepseek-v4-flash"
    settings.worker_model = "deepseek-v4-flash"
    settings.fallback_model = "deepseek-v4-flash"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError, match="Embedding provider"):
            await gateway.embeddings(["text"])
        assert calls == 0
        assert gateway.provider_attempts == ()
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_attempt_sink_receives_complete_attempt_before_graph_checkpoint(settings) -> None:
    enable_single_model_mock(settings)
    persisted: list[tuple[str, ProviderAttempt]] = []

    def sink(run_id: str, attempts: list[ProviderAttempt]) -> None:
        persisted.extend((run_id, attempt) for attempt in attempts)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})
        )
    )
    gateway = QwenGateway(settings, client, attempt_sink=sink)
    try:
        await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="sink-v1",
            run_id="run-sink",
        )
        assert len(persisted) == 1
        run_id, attempt = persisted[0]
        assert run_id == "run-sink"
        assert attempt.prompt_version == "sink-v1"
        assert attempt.response_sha256
    finally:
        await client.aclose()


@pytest.mark.parametrize("model_id", ["gpt-5.6", "unknown-model"])
def test_unknown_and_over_ceiling_models_are_rejected(settings, model_id: str) -> None:
    settings.planner_model = model_id
    expected = "hard maximum" if model_id == "gpt-5.6" else "Unknown model"
    with pytest.raises(ModelGatewayError, match=expected):
        QwenGateway(settings)


def test_fallback_cannot_be_more_expensive_than_primary(settings) -> None:
    settings.worker_model = "qwen-turbo"
    settings.fallback_model = "qwen-max"
    with pytest.raises(ModelGatewayError, match="fallback_model cannot be more expensive"):
        QwenGateway(settings)


@pytest.mark.asyncio
async def test_validated_model_selection_cannot_be_changed_after_gateway_creation(settings) -> None:
    enable_mock(settings)
    requested_models: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_models.append(json.loads(request.content)["model"])
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    settings.planner_model = "gpt-5.6"
    output, _ = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
    )
    await client.aclose()
    assert output.answer == "ok"
    assert requested_models == ["qwen-plus"]


@pytest.mark.asyncio
async def test_gateway_falls_back_after_invalid_primary_output(settings) -> None:
    enable_mock(settings)
    settings.worker_model = settings.planner_model
    settings.fallback_model = "deepseek-v4-flash"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = "not-json" if body["model"] == settings.planner_model else '{"answer":"fallback"}'
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
    )
    await client.aclose()
    assert output.answer == "fallback"
    assert meta.used_fallback is True
    # Local syntax recovery is attempted once; an independent provider gets
    # at most one semantic fallback request.
    assert meta.usage.provider_requests == 2


@pytest.mark.asyncio
async def test_gateway_embeddings(settings) -> None:
    enable_mock(settings)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0, 1]},
                    {"index": 0, "embedding": [1, 0]},
                ],
                "usage": {"prompt_tokens": 4, "total_tokens": 4},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    vectors = await gateway.embeddings(["first", "second"])
    await client.aclose()
    assert vectors == [[1.0, 0.0], [0.0, 1.0]]
    assert gateway.provider_attempts[-1].usage.total_tokens == 4
    with pytest.raises(ValueError, match="non-empty"):
        await gateway.embeddings([])


@pytest.mark.asyncio
async def test_invalid_provider_usage_is_discarded_but_attempt_and_reservation_settle_once(settings) -> None:
    enable_single_model_mock(settings)
    run_id = "run-invalid-usage"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"answer":"ok"}'}}],
                "usage": {"prompt_tokens": "not-a-number", "completion_tokens": -4},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = InvestigationStore(settings.database_url)
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        output, _ = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="usage-v1",
            run_id=run_id,
        )
        assert output.answer == "ok"
        assert len(gateway.provider_attempts) == 1
        assert gateway.provider_attempts[0].usage.total_tokens > 0
        assert store.settled_provider_usage(run_id).provider_requests == 1
        assert store.unsettled_reservation_ids(run_id) == []
    finally:
        await client.aclose()
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("include_usage", "usage", "expected_conservative"),
    [
        pytest.param(False, None, True, id="missing-usage"),
        pytest.param(True, None, True, id="null-usage"),
        pytest.param(
            True,
            {"prompt_tokens": "", "completion_tokens": ""},
            True,
            id="empty-counters",
        ),
        pytest.param(
            True,
            {"prompt_tokens": 0, "completion_tokens": 0},
            False,
            id="explicit-zero-counters",
        ),
    ],
)
async def test_usage_missing_values_fail_closed_but_explicit_zero_is_valid(
    settings,
    include_usage: bool,
    usage: object,
    expected_conservative: bool,
) -> None:
    enable_single_model_mock(settings)
    run_id = f"run-usage-boundary-{str(expected_conservative).lower()}-{include_usage}"

    def handler(_: httpx.Request) -> httpx.Response:
        body: dict[str, object] = {
            "choices": [{"message": {"content": '{"answer":"ok"}'}}],
        }
        if include_usage:
            body["usage"] = usage
        return httpx.Response(200, json=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = InvestigationStore(settings.database_url)
    gateway = QwenGateway(settings, client, usage_store=store)
    try:
        output, meta = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="usage-boundary-v1",
            run_id=run_id,
        )
    finally:
        await client.aclose()

    try:
        assert output.answer == "ok"
        attempt = gateway.provider_attempts_for(run_id)[0]
        settled = store.settled_provider_usage(run_id)
        if expected_conservative:
            assert attempt.usage.input_tokens > 0
            assert attempt.usage.output_tokens > 0
            assert attempt.unknown_usage is True
            assert attempt.provider_reported_usage.provider_requests == 0
            assert attempt.conservative_reserved_usage == attempt.usage
            assert meta.unknown_usage_attempts == 1
            assert meta.provider_reported_usage.provider_requests == 0
            assert meta.conservative_reserved_usage == attempt.usage
            assert settled.input_tokens == attempt.usage.input_tokens
            assert settled.output_tokens == attempt.usage.output_tokens
        else:
            assert attempt.usage.input_tokens == 0
            assert attempt.usage.output_tokens == 0
            assert attempt.unknown_usage is False
            assert attempt.provider_reported_usage == attempt.usage
            assert attempt.conservative_reserved_usage.provider_requests == 0
            assert meta.unknown_usage_attempts == 0
            assert meta.provider_reported_usage == attempt.usage
            assert meta.conservative_reserved_usage.provider_requests == 0
            assert settled.input_tokens == 0
            assert settled.output_tokens == 0
    finally:
        store.close()


@pytest.mark.asyncio
async def test_partial_provider_usage_preserves_known_tokens_and_reserves_unknown_output(settings) -> None:
    enable_single_model_mock(settings)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"answer":"ok"}'}}],
                "usage": {"prompt_tokens": 5},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        output, meta = await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="partial-usage-v1",
        )
    finally:
        await client.aclose()

    attempt = gateway.provider_attempts[0]
    assert output.answer == "ok"
    assert attempt.unknown_usage is True
    assert attempt.provider_reported_usage.input_tokens == 5
    assert attempt.provider_reported_usage.output_tokens == 0
    assert attempt.conservative_reserved_usage.input_tokens == 0
    assert attempt.conservative_reserved_usage.output_tokens > 0
    assert attempt.usage.input_tokens == 5
    assert attempt.usage.output_tokens == attempt.conservative_reserved_usage.output_tokens
    assert meta.provider_reported_usage == attempt.provider_reported_usage
    assert meta.conservative_reserved_usage == attempt.conservative_reserved_usage
    assert meta.unknown_usage_attempts == 1


@pytest.mark.asyncio
async def test_validation_failure_never_echoes_model_content_in_gateway_error(settings) -> None:
    enable_single_model_mock(settings)
    settings.model_structured_repair_attempts = 0
    sentinel = "sk-sentinel-should-never-escape"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({"answer": {"token": sentinel}})}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError) as captured:
            await gateway.structured(
                role="planner",
                system_prompt="system",
                user_prompt="user",
                output_model=Output,
                prompt_version="safe-error-v1",
            )
        assert sentinel not in str(captured.value)
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rows",
    [
        [{"index": 0, "embedding": [1]}, {"index": 0, "embedding": [2]}],
        [{"index": 0, "embedding": [1]}, {"index": 2, "embedding": [2]}],
        [{"index": 0, "embedding": [float("nan")]}, {"index": 1, "embedding": [2]}],
        [{"index": 0, "embedding": [1]}, {"index": 1, "embedding": [1, 2]}],
    ],
)
async def test_embeddings_reject_ambiguous_or_unsafe_vector_bindings(settings, rows) -> None:
    enable_mock(settings)
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=json.dumps({"data": rows}, allow_nan=True).encode())
        )
    )
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError, match="Malformed embedding"):
            await gateway.embeddings(["first", "second"])
        assert len(gateway.provider_attempts) == 1
        assert gateway.provider_attempts[0].error_type == "malformed_response"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_deterministic_demo_blocks_calls_before_transport(settings) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    with pytest.raises(ModelGatewayError, match="deterministic demo"):
        await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    with pytest.raises(ModelGatewayError, match="deterministic demo"):
        await gateway.embeddings(["text"])
    assert calls == 0
    await client.aclose()


@pytest.mark.asyncio
async def test_live_gateway_owned_client_closes_without_a_request(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "live"
    settings.allow_live_models = True
    settings.qwen_api_key = "test-key"
    gateway = QwenGateway(settings)
    await gateway.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("response_kind", ["rejected", "invalid-json", "missing-choice"])
async def test_chat_provider_failures_are_recorded_and_fail_closed(settings, response_kind: str) -> None:
    enable_mock(settings)

    def handler(_: httpx.Request) -> httpx.Response:
        if response_kind == "rejected":
            return httpx.Response(400, json={"error": "bad request"})
        if response_kind == "invalid-json":
            return httpx.Response(200, content=b"{")
        return httpx.Response(200, json={"usage": {"total_tokens": 1}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    with pytest.raises(ModelGatewayError, match="All configured models failed"):
        await gateway.structured(
            role="planner",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    assert gateway.provider_attempts
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("response_kind", ["rejected", "invalid-json", "missing-data", "wrong-count"])
async def test_embedding_provider_failures_are_closed_and_audited(settings, response_kind: str) -> None:
    enable_mock(settings)

    def handler(_: httpx.Request) -> httpx.Response:
        if response_kind == "rejected":
            return httpx.Response(403, json={"error": "forbidden"})
        if response_kind == "invalid-json":
            return httpx.Response(200, content=b"{")
        if response_kind == "missing-data":
            return httpx.Response(200, json={"not_data": []})
        return httpx.Response(200, json={"data": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    with pytest.raises(ModelGatewayError, match="Embedding response|Malformed embedding|count"):
        await gateway.embeddings(["text"])
    assert gateway.provider_attempts
    await client.aclose()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_model_tier", float("nan"), "finite non-negative"),
        ("embedding_model", "qwen-plus", "does not support embedding"),
        ("qwen_base_url", "https://models.example/v1?key=secret", "without query"),
    ],
)
def test_model_catalog_and_base_url_edge_cases_fail_closed(settings, field: str, value, message: str) -> None:
    setattr(settings, field, value)
    with pytest.raises(ModelGatewayError, match=message):
        QwenGateway(settings)
