from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from security_agent.llm import ModelGateway, ModelGatewayError, SideQuestionModelError


class Output(BaseModel):
    answer: str


@pytest.mark.asyncio
async def test_side_question_uses_streaming_and_keeps_the_frozen_request(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    snapshot = {
        "model_id": "frozen-model",
        "request": {"messages": [{"role": "system", "content": "frozen context"}]},
        "side_question_output_tokens": 48,
    }

    deltas = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["model"] == "frozen-model"
        assert body["messages"][0]["role"] == "system"
        assert "JSON Schema" in body["messages"][0]["content"]
        assert "frozen context" in body["messages"][1]["content"]
        assert body["messages"][-1] == {"role": "user", "content": "why?"}
        assert body["max_tokens"] == 48
        assert body["stream"] is True
        assert body["stream_options"] == {"include_usage": True}
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=(
            'data: {"choices":[{"delta":{"content":"Ans"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"wer"}}]}\n\n'
            'data: {"choices":[],"usage":{"prompt_tokens":500,"completion_tokens":1}}\n\n'
            'data: [DONE]\n\n'
        ))

    async def on_delta(delta):
        deltas.append(delta)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result, usage = await ModelGateway(settings, client).answer_side_question(snapshot, "why?", on_delta)
    assert result == "Answer"
    assert deltas == ["Ans", "wer"]
    assert usage["prompt_tokens"] == 500
    assert snapshot["request"]["messages"] == [{"role": "system", "content": "frozen context"}]


@pytest.mark.asyncio
async def test_side_question_classifies_empty_and_rejected_model_responses(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    snapshot = {"model_id": "model", "request": {"messages": [{"role": "user", "content": "context"}]}}
    responses = [
        httpx.Response(200, headers={"content-type": "text/event-stream"}, text=(
            'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":0}}\n\n'
            'data: [DONE]\n\n'
        )),
        httpx.Response(429, json={"error": {"message": "private upstream details"}}),
    ]

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: responses.pop(0))) as client:
        gateway = ModelGateway(settings, client)
        with pytest.raises(SideQuestionModelError) as empty:
            await gateway.answer_side_question(snapshot, "why?")
        assert empty.value.code == "model_empty_response"
        with pytest.raises(SideQuestionModelError) as limited:
            await gateway.answer_side_question(snapshot, "why?")
        assert limited.value.code == "model_rate_limited"
        assert "private upstream details" not in str(limited.value)


@pytest.mark.asyncio
async def test_gateway_retries_retryable_response(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    settings.fallback_model = "fallback-model"
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(429, json={"error": "limited"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({"answer": "ok"})}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = ModelGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
    )
    await client.aclose()
    assert output.answer == "ok"
    assert meta.model_id == settings.planner_model
    assert calls == 3


@pytest.mark.asyncio
async def test_gateway_requires_enabled_credentials(settings) -> None:
    gateway = ModelGateway(settings)
    with pytest.raises(ModelGatewayError, match="demo mode"):
        await gateway.structured(
            role="worker",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    settings.demo_mode = False
    with pytest.raises(ModelGatewayError, match="not configured"):
        await gateway.structured(
            role="worker",
            system_prompt="system",
            user_prompt="user",
            output_model=Output,
            prompt_version="v1",
        )
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_falls_back_after_invalid_primary_output(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    settings.fallback_model = "fallback-model"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = "not-json" if body["model"] == settings.planner_model else '{"answer":"fallback"}'
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = ModelGateway(settings, client)
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


@pytest.mark.asyncio
async def test_gateway_accepts_sse_when_provider_ignores_nonstream_request(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"

    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content).get("stream") is not True
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=(
            'data: {"choices":[{"delta":{"content":"{\\"answer\\":\\"ok\\"}"}}]}\n\n'
            'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2}}\n\n'
            'data: [DONE]\n\n'
        ))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result, meta = await ModelGateway(settings, client).structured(
            role="worker", system_prompt="system", user_prompt="user",
            output_model=Output, prompt_version="v1",
        )
    assert result.answer == "ok"
    assert meta.usage["total_tokens"] == 6


@pytest.mark.asyncio
async def test_probe_requires_text_from_streamed_provider(settings) -> None:
    async def observer(_kind: str, _payload: dict) -> None:
        pass

    responses = [
        'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n'
        'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":1}}\n\n'
        'data: [DONE]\n\n',
        'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":0}}\n\n'
        'data: [DONE]\n\n',
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["stream"] is True
        assert payload['stream_options'] == {'include_usage': True}
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              text=responses.pop(0))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gateway = ModelGateway(settings, client)
        result = await gateway.probe_model("https://example.test/v1", "test-key", "model", observer)
        assert result["ok"] and result["usage"]["total_tokens"] == 5
        with pytest.raises(ModelGatewayError, match="Model returned no text"):
            await gateway.probe_model("https://example.test/v1", "test-key", "model", observer)


@pytest.mark.asyncio
async def test_gateway_embeddings(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0, 1]},
                    {"index": 0, "embedding": [1, 0]},
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = ModelGateway(settings, client)
    vectors = await gateway.embeddings(["first", "second"])
    await client.aclose()
    assert vectors == [[1.0, 0.0], [0.0, 1.0]]
    with pytest.raises(ValueError, match="non-empty"):
        await gateway.embeddings([])


@pytest.mark.asyncio
async def test_streaming_gateway_emits_deltas_and_completion(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    observed: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["stream"] is True
        assert body["response_format"] == {"type": "json_object"}
        content = (
            'data: {"choices":[{"delta":{"content":"{\\"answer\\":"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"\\"ok\\"}"},"finish_reason":"stop"}]}\n\n'
            'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}\n\n'
            "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=content, headers={"content-type": "text/event-stream"})

    async def observer(event_type: str, payload: dict) -> None:
        observed.append((event_type, payload))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = ModelGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
        stream_observer=observer,
    )
    await client.aclose()
    assert output.answer == "ok"
    assert [item[0] for item in observed] == [
        "llm.prompt.selected",
        "llm.stream.started",
        "llm.stream.delta",
        "llm.stream.delta",
        "llm.stream.completed",
    ]
    assert meta.usage["total_tokens"] == 6
    assert observed[-1][1]["content"] == '{"answer":"ok"}'


@pytest.mark.asyncio
async def test_streaming_gateway_emits_failure_before_fallback(settings) -> None:
    settings.demo_mode = False
    settings.model_api_key = "test-key"
    settings.fallback_model = "fallback"
    observed: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        model = json.loads(request.content)["model"]
        if model == settings.planner_model:
            return httpx.Response(400, json={"error": "unknown model"})
        content = (
            'data: {"choices":[{"delta":{"content":"{\\"answer\\":'
            '\\"fallback\\"}"},"finish_reason":"stop"}]}\n\n'
            "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=content, headers={"content-type": "text/event-stream"})

    async def observer(event_type: str, payload: dict) -> None:
        observed.append((event_type, payload))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = ModelGateway(settings, client)
    output, meta = await gateway.structured(
        role="planner",
        system_prompt="system",
        user_prompt="user",
        output_model=Output,
        prompt_version="v1",
        stream_observer=observer,
    )
    await client.aclose()
    assert output.answer == "fallback"
    assert meta.used_fallback is True
    assert any(event_type == "llm.stream.failed" for event_type, _ in observed)
