from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.coordinator import CoordinatorStore, ModelInvocationRow
from secmind.investigation.store import InvestigationStore
from secmind.llm import ModelGatewayError, QwenGateway, _canonical_sha256, _extract_first_json_value
from secmind.model_router import (
    FALLBACK_ROUTE_PROFILE,
    MODEL_ROUTER_VERSION,
    ModelLane,
    ModelRouter,
    ModelTaskKind,
)


class RoutedOutput(BaseModel):
    answer: str


def enable_mock(settings) -> None:
    settings.demo_mode = False
    settings.model_mode = "mock"


@pytest.mark.parametrize(
    ("task_kind", "expected_lane", "expected_model"),
    [
        (ModelTaskKind.PLANNING, ModelLane.REASONING, "qwen-plus"),
        (ModelTaskKind.PRIMARY_REVIEW, ModelLane.REASONING, "qwen-plus"),
        (ModelTaskKind.CRITIC_REVIEW, ModelLane.LIGHTWEIGHT, "qwen-turbo"),
        (ModelTaskKind.PROMPT_OPTIMIZATION, ModelLane.LIGHTWEIGHT, "qwen-turbo"),
        (ModelTaskKind.EXTRACTION, ModelLane.LIGHTWEIGHT, "qwen-turbo"),
    ],
)
def test_router_assigns_reviewed_task_lanes(settings, task_kind, expected_lane, expected_model) -> None:
    route = ModelRouter(QwenGateway(settings).policy).route(task_kind, role="worker")

    assert route.lane is expected_lane
    assert route.primary.model_id == expected_model
    assert route.router_version == MODEL_ROUTER_VERSION


def test_router_preserves_legacy_role_fallback(settings) -> None:
    router = ModelRouter(QwenGateway(settings).policy)

    assert router.route(None, role="planner").primary.model_id == settings.planner_model
    assert router.route(None, role="worker").primary.model_id == settings.worker_model
    with pytest.raises(ValueError):
        router.route("unreviewed-task", role="planner")


@pytest.mark.asyncio
async def test_route_identity_is_hashed_and_returned_without_changing_provider_bytes(settings) -> None:
    enable_mock(settings)
    settings.worker_model = settings.planner_model
    settings.fallback_model = settings.planner_model
    payloads: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payloads.append(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        _, planning = await gateway.structured(
            role="worker",
            task_kind=ModelTaskKind.PLANNING,
            system_prompt="system",
            user_prompt="user",
            output_model=RoutedOutput,
            prompt_version="route-v1",
        )
        _, extraction = await gateway.structured(
            role="worker",
            task_kind=ModelTaskKind.EXTRACTION,
            system_prompt="system",
            user_prompt="user",
            output_model=RoutedOutput,
            prompt_version="route-v1",
        )
    finally:
        await client.aclose()

    assert payloads[0] == payloads[1]
    assert planning.request_sha256 != extraction.request_sha256
    assert planning.route_task_kind == "planning"
    assert planning.route_lane == "reasoning"
    assert extraction.route_task_kind == "extraction"
    assert extraction.route_lane == "lightweight"
    assert planning.router_version == extraction.router_version == MODEL_ROUTER_VERSION


@pytest.mark.asyncio
async def test_retry_then_schema_failure_persists_hash_without_same_provider_replay(settings) -> None:
    enable_mock(settings)
    settings.model_max_attempts = 2
    settings.model_structured_repair_attempts = 1
    settings.planner_model = "qwen-plus"
    settings.fallback_model = "qwen-turbo"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        ordinal = len(requests)
        if ordinal == 1:
            return httpx.Response(429, json={"error": "retry"})
        if ordinal == 2:
            return httpx.Response(200, json={"choices": [{"message": {"content": "not-json"}}]})
        if ordinal == 3:
            return httpx.Response(400, json={"error": "repair rejected"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError):
            await gateway.structured(
                role="planner",
                task_kind=ModelTaskKind.PLANNING,
                system_prompt="system",
                user_prompt="user",
                output_model=RoutedOutput,
                prompt_version="route-audit-v1",
                run_id="run-route-audit",
            )
    finally:
        await client.aclose()

    attempts = list(gateway.provider_attempts)
    assert len(attempts) == len(requests) == 2
    expected_hashes = [
        _canonical_sha256(
            {
                "endpoint": str(request.url),
                "payload": json.loads(request.content),
            }
        )
        for request in requests
    ]
    assert [attempt.provider_request_sha256 for attempt in attempts] == expected_hashes
    assert [attempt.succeeded for attempt in attempts] == [False, True]
    assert [attempt.model_id for attempt in attempts] == ["qwen-plus", "qwen-plus"]
    assert {(attempt.task_kind, attempt.lane, attempt.router_version) for attempt in attempts} == {
        ("planning", "reasoning", MODEL_ROUTER_VERSION)
    }

    coordinator = CoordinatorStore(settings.database_url)
    try:
        coordinator.record_model_attempts("run-route-audit", attempts)
        with Session(coordinator.engine) as session:
            rows = list(session.scalars(select(ModelInvocationRow)).all())
        persisted = {row.provider_request_id: row for row in rows}
        assert set(persisted) == {attempt.provider_request_id for attempt in attempts}
        for attempt in attempts:
            row = persisted[attempt.provider_request_id]
            assert row.request_hash == attempt.provider_request_sha256
            assert (row.task_kind, row.model_lane, row.router_version) == (
                attempt.task_kind,
                attempt.lane,
                attempt.router_version,
            )
    finally:
        coordinator.close()


@pytest.mark.parametrize(
    ("model_id", "format_type"),
    [
        ("qwen-plus", "json_object"),
        ("deepseek-v4-flash", "json_object"),
        ("gpt-5.4", "json_schema"),
        ("gpt-5.6-luna", "json_schema"),
        ("gpt-5.6-terra", "json_schema"),
    ],
)
def test_provider_specific_structured_output_contract(settings, model_id: str, format_type: str) -> None:
    settings.planner_model = model_id
    settings.worker_model = model_id
    settings.fallback_model = model_id
    gateway = QwenGateway(settings)

    payload = gateway._chat_payload(
        model_id,
        "trusted system",
        "untrusted input",
        RoutedOutput.model_json_schema(),
    )

    assert payload["response_format"]["type"] == format_type
    if format_type == "json_object":
        assert "Return only one JSON object matching this JSON schema" in payload["messages"][0]["content"]
    else:
        assert payload["response_format"]["json_schema"]["schema"] == RoutedOutput.model_json_schema()


def test_openai_compatible_json_object_fallback_keeps_schema_in_trusted_prompt(settings) -> None:
    settings.planner_model = "gpt-5.6-luna"
    settings.worker_model = "gpt-5.6-luna"
    settings.fallback_model = "gpt-5.6-luna"
    settings.model_structured_output_mode = "json_object"
    gateway = QwenGateway(settings)

    payload = gateway._chat_payload(
        "gpt-5.6-luna",
        "trusted system",
        "untrusted input",
        RoutedOutput.model_json_schema(),
    )

    assert payload["response_format"] == {"type": "json_object"}
    assert "Return only one JSON object matching this JSON schema" in payload["messages"][0]["content"]
    assert '"answer"' in payload["messages"][0]["content"]


def test_terra_uses_configured_reasoning_without_enabling_fallback_thinking(settings) -> None:
    settings.planner_model = "gpt-5.6-terra"
    settings.worker_model = "gpt-5.6-terra"
    settings.fallback_model = "gpt-5.6-terra"
    settings.model_reasoning_effort = "high"
    settings.model_fallback_thinking_enabled = False
    gateway = QwenGateway(settings)

    primary = gateway._chat_payload(
        "gpt-5.6-terra",
        "trusted system",
        "untrusted input",
        RoutedOutput.model_json_schema(),
    )
    fallback = gateway._chat_payload(
        "gpt-5.6-terra",
        "trusted system",
        "untrusted input",
        RoutedOutput.model_json_schema(),
        route_profile=FALLBACK_ROUTE_PROFILE,
    )

    assert primary["reasoning_effort"] == "high"
    assert "reasoning_effort" not in fallback


def test_bounded_json_extractor_handles_strings_and_returns_only_first_candidate() -> None:
    text = 'preface {"answer":"escaped \\"quote\\" and } bracket"} trailing {"answer":"second"}'
    candidate = _extract_first_json_value(text, max_chars=1_000, max_depth=8)

    assert candidate is not None
    assert json.loads(candidate) == {"answer": 'escaped "quote" and } bracket'}
    assert "second" not in candidate
    assert _extract_first_json_value("prefix {]", max_chars=100, max_depth=8) is None
    assert _extract_first_json_value("x" * 101 + "{}", max_chars=100, max_depth=8) is None
    assert _extract_first_json_value('{"a":{"b":{}}}', max_chars=100, max_depth=2) is None


def test_parser_recovers_one_bounded_candidate_and_fails_closed_on_its_schema(settings) -> None:
    gateway = QwenGateway(settings)

    recovered = gateway._parse_model('preface ```json\n{"answer":"ok"}\n``` suffix', RoutedOutput)
    assert recovered.answer == "ok"
    with pytest.raises(ValidationError):
        gateway._parse_model('{"wrong":1} {"answer":"must-not-be-scanned"}', RoutedOutput)

    settings.model_json_recovery_max_chars = 1_024
    with pytest.raises(json.JSONDecodeError):
        gateway._parse_model("x" * 1_025, RoutedOutput)


@pytest.mark.asyncio
async def test_recovered_json_keeps_exact_raw_cas_bytes_and_replays(settings) -> None:
    enable_mock(settings)
    run_id = "run-bounded-json-replay"
    raw = 'provider preface\n```json\n{"answer":"recovered"}\n```\nprovider suffix'
    provider_calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal provider_calls
        provider_calls += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": raw}}]})

    store = InvestigationStore(settings.database_url)
    artifacts = ContentAddressedArtifactStore(settings.artifact_root)
    first_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    first = QwenGateway(settings, first_client, usage_store=store, artifact_store=artifacts)
    try:
        output, first_meta = await first.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=RoutedOutput,
            prompt_version="bounded-json-v1",
            run_id=run_id,
            durable_call_key="primary:bounded-json",
        )
    finally:
        await first_client.aclose()

    assert output.answer == "recovered"
    assert artifacts.read(first_meta.raw_response_artifact_id) == raw.encode("utf-8")

    def forbid_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("durable JSON recovery must replay the raw receipt")

    second_client = httpx.AsyncClient(transport=httpx.MockTransport(forbid_request))
    second = QwenGateway(settings, second_client, usage_store=store, artifact_store=artifacts)
    try:
        replay, replay_meta = await second.structured(
            role="planner",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
            system_prompt="system",
            user_prompt="user",
            output_model=RoutedOutput,
            prompt_version="bounded-json-v1",
            run_id=run_id,
            durable_call_key="primary:bounded-json",
        )
    finally:
        await second_client.aclose()
        store.close()

    assert replay.answer == "recovered"
    assert replay_meta.replayed_from_receipt is True
    assert replay_meta.router_version == MODEL_ROUTER_VERSION
    assert provider_calls == 1
