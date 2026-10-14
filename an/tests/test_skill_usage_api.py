from __future__ import annotations

import httpx
import pytest
from security_agent.api import create_app
from security_agent.schemas import AgentState, TaskRequest


@pytest.mark.asyncio
async def test_engine_statistics_auth_mapping_missing_reference_and_detail(settings, monkeypatch):
    settings.secmind_operator_token = "test-engine-token"  # noqa: S105 - synthetic credential
    settings.reverse_base_url = "http://engine.test"
    app = create_app(settings)
    ledger = app.state.service.ledger
    ledger.save_state(
        AgentState(
            run_id="local-1", task=TaskRequest(objective="test"), external_execution={"remote_run_id": "remote-1"}
        )
    )
    ledger.save_state(AgentState(run_id="legacy", task=TaskRequest(objective="test")))
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == "Bearer test-engine-token"
        event = {"event_id": "event-1", "run_id": "remote-1", "payload": {"usage_id": "operation-1"}}
        if "/events/" in request.url.path:
            return httpx.Response(200, json=event)
        assert request.url.params["run_id"] == "remote-1"
        assert request.url.params["skill_id"] == "project-inventory"
        return httpx.Response(
            200,
            json={
                "events": [event],
                "skills": [],
                "totals": {"loads": 0, "load_failures": 0, "calls": 0},
                "total_events": 1,
            },
        )

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.get(
            "/api/v1/skills/usage", params={"run_id": "local-1", "skill_id": "project-inventory", "offset": 20}
        )
        assert result.status_code == 200, result.text
        assert result.json()["events"][0]["workbench_run_ids"] == ["local-1"]
        assert result.json()["source"] == "secmind_execution_ledger"
        event = await client.get("/api/v1/skills/usage/events/event-1")
        assert event.json()["workbench_run_ids"] == ["local-1"]
        previous = len(requests)
        no_ref = await client.get("/api/v1/skills/usage?run_id=legacy")
        assert no_ref.status_code == 200 and no_ref.json()["unavailable_reason"]
        assert no_ref.json()["totals"]["calls"] == 0
        assert (await client.get("/api/v1/skills/usage?run_id=missing")).status_code == 404
        assert (await client.get("/api/v1/skills/usage?limit=201")).status_code == 422
        assert (await client.get("/api/v1/skills/usage?event_type=tool.started")).status_code == 422
        assert len(requests) == previous
        assert "test-engine-token" not in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(404, 404), (401, 502), (500, 502)])
async def test_bridge_engine_errors_are_controlled(settings, monkeypatch, status, expected):
    app = create_app(settings)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client(
            transport=httpx.MockTransport(lambda _: httpx.Response(status, text="private engine detail")), **kw
        ),
    )
    async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/api/v1/skills/usage/events/missing")
    assert response.status_code == expected
    assert "private engine detail" not in response.text


@pytest.mark.asyncio
async def test_bridge_invalid_json_and_connection_failure(settings, monkeypatch):
    app = create_app(settings)
    real_client = httpx.AsyncClient

    def handler(request):
        if request.url.path.endswith("/usage"):
            return httpx.Response(200, text="invalid json")
        raise httpx.ConnectError("private connection information")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for path in ("/api/v1/skills/usage", "/api/v1/skills/usage/events/missing"):
            response = await client.get(path)
            assert response.status_code == 502 and "private" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], None, {"events": [None]}, {"run_id": 3, "payload": {}}])
async def test_bridge_malformed_engine_shape_is_controlled(settings, monkeypatch, body):
    app = create_app(settings)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)), **kw),
    )
    async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for path in ("/api/v1/skills/usage", "/api/v1/skills/usage/events/event-1"):
            response = await client.get(path)
            assert response.status_code == 502
            assert response.json()["detail"] == "分析引擎技能统计暂不可用"
