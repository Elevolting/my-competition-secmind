from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from secmind.llm import QwenGateway
from secmind.model_router import ModelTaskKind
from secmind.model_snapshots import (
    ModelConfiguration,
    ModelSnapshotRow,
    ModelSnapshotStore,
    SnapshotParent,
    canonical,
    sanitize_snapshot,
)


class Output(BaseModel):
    answer: str


@pytest.fixture
def store(settings):
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    value = ModelSnapshotStore(engine, sanitize=sanitize_snapshot)
    yield value
    engine.dispose()


def configuration() -> ModelConfiguration:
    return ModelConfiguration(
        base_url="https://model.test/v1", provider="compatible-api", model_id="model",
        planner_model="model", worker_model="worker", fallback_model="fallback",
    )


def request(text="context") -> dict:
    return {"model": "model", "messages": [{"role": "user", "content": text}], "temperature": 0.1}


def capture(store, parent, text="context"):
    return store.capture(parent=parent, configuration=configuration(), request=request(text),
                         provenance={"call_id": "call-1", "attempt": 1})


def row_count(store):
    with Session(store.engine) as session:
        return session.scalar(select(func.count()).select_from(ModelSnapshotRow))


def enable(settings):
    settings.demo_mode = False
    settings.model_mode = "mock"
    settings.qwen_api_key = "private-test-api-key"


def gateway(settings, client, store):
    return QwenGateway(settings, client, snapshot_store=store)


async def call(value, **kwargs):
    return await value.structured(
        role="planner", system_prompt="system", user_prompt="context",
        output_model=Output, prompt_version="snapshot-test-v1", **kwargs,
    )


def test_immutable_versions_survive_reopen_and_configuration_checks(settings, store):
    parent = SnapshotParent("run-1", "secmind")
    first = capture(store, parent)
    second = capture(store, parent, "new context")
    assert second["version"] > first["version"]
    first["request"]["messages"][0]["content"] = "client changed"
    assert store.frozen(parent, first["snapshot_id"], configuration())["request"] == request()
    reopened = ModelSnapshotStore(store.engine, sanitize=sanitize_snapshot, initialize_schema=False)
    assert reopened.latest(parent) == second
    assert reopened.latest(SnapshotParent("old-task", "secmind")) is None
    with pytest.raises(LookupError):
        store.frozen(SnapshotParent("run-2", "secmind"), second["snapshot_id"], configuration())
    for changes in ({"base_url": "https://other.test/v1"}, {"model_id": "changed"},
                    {"worker_model": "changed"}, {"provider": "another"}):
        with pytest.raises(ValueError, match="configuration changed"):
            store.frozen(parent, second["snapshot_id"], replace(configuration(), **changes))


@pytest.mark.parametrize("url", [
    "https://user:password@model.test/v1", "https://model.test/v1?api_key=value",
    "https://model.test/v1#key", "file:///tmp/model",
])
def test_model_configuration_rejects_credential_bearing_addresses(url):
    with pytest.raises(ValueError):
        replace(configuration(), base_url=url)


def test_tool_pairs_and_deep_nested_schema_are_preserved_without_mutation(store):
    parent = SnapshotParent("run-tools", "secmind", "step-1", "intent-A-attempt-1")
    payload = request()
    payload["messages"] += [
        {"role": "assistant", "tool_calls": [
            {"id": "tool-1", "type": "function", "function": {"name": "read", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "tool-1", "content": '{"password": "sample-secret"}'},
        {"role": "user", "content": "explain"},
    ]
    schema = {"type": "string"}
    for _ in range(20):
        schema = {"type": "object", "properties": {"child": schema}}
    payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "Output", "schema": schema}}
    raw = canonical(payload)
    document = store.capture(parent=parent, configuration=configuration(), request=payload, provenance={})
    assert canonical(payload) == raw
    assert "sample-secret" not in canonical(document)
    assert document["redacted"]
    assert document["request"]["response_format"] == payload["response_format"]
    assert document["request"]["messages"][1]["tool_calls"][0]["id"] == "tool-1"
    assert document["request"]["messages"][2]["tool_call_id"] == "tool-1"
    assert document["request_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    payload["messages"][0]["content"] = "changed after capture"
    assert store.latest(parent)["request"]["messages"][0]["content"] == "context"


@pytest.mark.parametrize("messages", [
    [],
    [{"role": "tool", "tool_call_id": "missing", "content": "value"}],
    [{"role": "assistant", "tool_calls": [{"id": "missing"}]}],
    [{"role": "user", "tool_calls": [{"id": "invalid"}]}],
])
def test_unusable_tool_context_is_not_persisted(store, messages):
    payload = request()
    payload["messages"] = messages
    with pytest.raises(ValueError):
        store.capture(parent=SnapshotParent("run-1", "secmind"), configuration=configuration(),
                      request=payload, provenance={})
    assert row_count(store) == 0


def test_header_secrets_and_invalid_json_are_rejected(store):
    for changes in ({"headers": {"Authorization": "Bearer test-secret"}}, {"temperature": float("nan")},
                    {"model": "different"}, {"messages": [{"role": "user", "content": "x" * 2_000_000}]}):
        with pytest.raises(ValueError):
            store.capture(parent=SnapshotParent("run-1", "secmind"), configuration=configuration(),
                          request={**request(), **changes}, provenance={})
    assert row_count(store) == 0


@pytest.mark.asyncio
async def test_snapshot_exists_before_http_send_and_does_not_change_actual_request(settings, store):
    enable(settings)
    parent = SnapshotParent("run-send", "secmind")
    seen = []

    def handler(http_request):
        body = json.loads(http_request.content)
        document = store.latest(parent)
        assert document is not None
        assert document["boundary"] == "request_send"
        assert document["model_id"] == body["model"]
        assert document["request_sha256"] == hashlib.sha256(canonical(body).encode()).hexdigest()
        assert document["provenance"]["attempt"] == 1
        assert document["provenance"]["prompt_version"]
        assert body["messages"][-1]["content"] == "password=sample-secret"
        assert "sample-secret" not in canonical(document)
        assert "private-test-api-key" not in canonical(document)
        assert http_request.headers["Authorization"] == "Bearer private-test-api-key"
        seen.append(document)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer": "ok"}'}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        value = gateway(settings, client, store)
        output, meta = await value.structured(
            role="planner", system_prompt="system", user_prompt="password=sample-secret",
            output_model=Output, prompt_version="snapshot-test-v1",
            run_id=parent.run_id, call_purpose="primary",
        )
    assert output.answer == "ok"
    assert len(seen) == 1
    assert seen[0]["provenance"]["prompt_version"] == meta.prompt_version
    assert row_count(store) == 1


@pytest.mark.asyncio
async def test_only_explicit_primary_requests_replace_main_snapshot(settings, store):
    enable(settings)
    parent = SnapshotParent("run-purpose", "secmind")
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})
    )) as client:
        value = gateway(settings, client, store)
        await call(value, run_id=parent.run_id, call_purpose="primary")
        first = store.latest(parent)
        for purpose in ("auxiliary", "summary", "probe", "sidequestion"):
            await call(value, run_id=parent.run_id, call_purpose=purpose)
        await call(value, run_id=parent.run_id)
        await call(value, call_purpose="primary")
        settings.qwen_api_key = "rotated-test-api-key"
        assert store.frozen(parent, first["snapshot_id"], value.snapshot_configuration(first["model_id"])) == first
    assert store.latest(parent) == first
    assert row_count(store) == 1


@pytest.mark.asyncio
async def test_parallel_step_parents_are_isolated(settings, store):
    enable(settings)
    parents = [SnapshotParent("shared-run", "secmind", f"step-{i}", f"intent-{i}-attempt-1") for i in range(6)]
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})
    )) as client:
        value = gateway(settings, client, store)
        await asyncio.gather(*(call(value, run_id=p.run_id, step_id=p.step_id, worker_id=p.worker_id,
                                    call_purpose="primary") for p in parents))
    documents = [store.latest(p) for p in parents]
    assert len({d["snapshot_id"] for d in documents}) == len(parents)
    assert len({d["version"] for d in documents}) == len(parents)
    for parent, document in zip(parents, documents, strict=True):
        assert document["parent"] == vars(parent)
    assert store.latest(SnapshotParent("shared-run", "secmind")) is None


@pytest.mark.asyncio
async def test_snapshot_failure_is_observational_and_logs_no_secret(settings, store, monkeypatch, caplog):
    enable(settings)
    def fail(**_kwargs):
        raise RuntimeError("private-test-api-key")
    monkeypatch.setattr(store, "capture", fail)
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})
    )) as client:
        output, _ = await call(gateway(settings, client, store), run_id="run-failure", call_purpose="primary")
    assert output.answer == "ok"
    assert row_count(store) == 0
    assert "capture failed (RuntimeError)" in caplog.text
    assert "private-test-api-key" not in caplog.text


@pytest.mark.asyncio
async def test_retries_capture_each_real_send_and_final_model(settings, store):
    enable(settings)
    settings.planner_model = "qwen-plus"
    settings.worker_model = settings.planner_model
    settings.fallback_model = "qwen-turbo"
    sent = []
    parent = SnapshotParent("run-retry", "secmind")

    def handler(http_request):
        body = json.loads(http_request.content)
        document = store.latest(parent)
        assert document["request_sha256"] == hashlib.sha256(canonical(body).encode()).hexdigest()
        sent.append(document)
        if len(sent) == 1:
            return httpx.Response(429)
        if body["model"] == settings.planner_model:
            return httpx.Response(400)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        value = gateway(settings, client, store)
        output, meta = await call(
            value,
            run_id=parent.run_id,
            call_purpose="primary",
            task_kind=ModelTaskKind.PRIMARY_REVIEW,
        )
        assert output.answer == "ok"
        assert meta.used_fallback
        assert store.latest(parent)["model_id"] == settings.fallback_model
        # PRIMARY_REVIEW intentionally gives the primary provider one bounded
        # attempt before switching to the configured fallback.  The snapshot
        # store must still capture both real provider sends.
        assert len(sent) == 2
        assert sent[0]["provenance"]["attempt"] == 1
        assert sent[1]["provenance"]["attempt"] == 2
        assert row_count(store) == len(sent)
        assert store.frozen(
            parent, sent[0]["snapshot_id"], value.snapshot_configuration(sent[0]["model_id"]),
        ) == sent[0]

