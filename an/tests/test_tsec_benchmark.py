import json

import httpx
import pytest
from fastapi import FastAPI

from security_agent.config import Settings
from security_agent.tsec_api import register_tsec
from security_agent.tsec_benchmark import TSecBenchmarkClient, TSecConfig, TSecError

TOKEN = "11111111-1111-4111-8111-111111111111"  # noqa: S105 - synthetic test credential


def client_for(handler):
    return TSecBenchmarkClient(TSecConfig("https://benchmark.test/", TOKEN),
                               transport=httpx.MockTransport(handler))


async def test_full_protocol_multiple_flags_and_explicit_hint():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["BENCHMARK_TOKEN"] == TOKEN
        assert TOKEN not in str(request.url)
        assert "authorization" not in request.headers
        action = request.url.path.rsplit("/", 1)[-1]
        if action == "challenges":
            assert request.method == "GET"
            return httpx.Response(200, json=[{"unique_code": "题目 & 1", "flag_count": 2}])
        if action == "submit":
            assert request.method == "POST"
            assert request.headers["content-type"] == "application/json"
            data = json.loads(request.content)
            assert data["unique_code"] == "题目 & 1"
            return httpx.Response(200, json={"correct": True, "correct_flag_count": len(calls) - 2,
                                             "total_flag_count": 2, "awarded": 50})
        assert request.url.params["unique_code"] == "题目 & 1"
        assert request.method == ("GET" if action == "hint" else "POST")
        return httpx.Response(200, json={"unique_code": "题目 & 1", "container_addr": ["10.0.0.1:80"],
                                         "hint": None, "closed": True})

    client = client_for(handler)
    assert (await client.list_challenges())[0]["flag_count"] == 2
    assert (await client.start("题目 & 1"))["container_addr"] == ["10.0.0.1:80"]
    assert (await client.submit("题目 & 1", "flag{one}"))["correct_flag_count"] == 1
    assert (await client.submit("题目 & 1", "flag{two}"))["correct_flag_count"] == 2
    assert len(calls) == 4  # Neither hints nor additional submissions are automatic.
    assert (await client.hint("题目 & 1"))["hint"] is None
    assert (await client.close("题目 & 1"))["closed"] is True


@pytest.mark.parametrize("status,code", [(404, "task_not_found"), (404, "challenge_not_found"),
                                        (409, "invalid_state"), (409, "duplicate"),
                                        (503, "resource_unavailable"), (500, "internal_error")])
async def test_business_errors_preserve_codes_without_retry(status, code):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"code": code, "message": "upstream message", "detail": {"x": 1}})

    with pytest.raises(TSecError) as error:
        await client_for(handler).submit("web", "flag{one}")
    assert (error.value.status_code, error.value.code, error.value.detail) == (status, code, {"x": 1})
    assert len(calls) == 1


async def test_timeout_and_non_json_are_actionable():
    def timeout(request):
        raise httpx.ReadTimeout("secret request details", request=request)

    with pytest.raises(TSecError, match="ReadTimeout") as error:
        await client_for(timeout).start("web")
    assert error.value.code == "platform_unavailable"
    assert "secret" not in str(error.value)
    with pytest.raises(TSecError) as error:
        await client_for(lambda _: httpx.Response(200, text="<html>proxy error</html>")).list_challenges()
    assert error.value.code == "invalid_response"


async def test_redirect_is_not_followed_and_secret_errors_are_redacted():
    calls = []

    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://elsewhere.test"})

    with pytest.raises(TSecError) as error:
        await client_for(redirect).list_challenges()
    assert error.value.code == "unexpected_redirect"
    assert len(calls) == 1
    with pytest.raises(TSecError) as error:
        await client_for(lambda _: httpx.Response(404, json={"code": "task_not_found", "message": TOKEN,
                                                            "detail": {"token": TOKEN}})).list_challenges()
    assert TOKEN not in str(error.value)
    assert TOKEN not in json.dumps(error.value.detail)
    assert TOKEN not in repr(TSecConfig("https://benchmark.test", TOKEN))


@pytest.mark.parametrize("flag", ["", "x" * 4097])
async def test_invalid_flag_does_not_reach_platform(flag):
    def unexpected(_):
        pytest.fail("Invalid input reached the platform")

    with pytest.raises(TSecError) as error:
        await client_for(unexpected).submit("web", flag)
    assert error.value.status_code == 422


async def test_local_adapter_and_framework_validation(settings):
    settings.tsec_base_url = "https://benchmark.test"
    settings.tsec_token = TOKEN
    app = FastAPI()
    register_tsec(app, settings)
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/submit"):
            return httpx.Response(200, json={"correct": False, "awarded": 0})
        return httpx.Response(200, json=[])

    app.state.tsec_client.transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://local") as client:
        assert (await client.get("/api/v1/tsec/challenges")).json() == []
        response = await client.post("/api/v1/tsec/challenges/submit", json={"unique_code": "web", "flag": "wrong"})
        assert response.json() == {"correct": False, "awarded": 0}
        invalid = await client.post("/api/v1/tsec/challenges/submit", json={"unique_code": "web", "flag": ""})
        assert invalid.status_code == 422
        assert (await client.post("/api/v1/tsec/challenges/start")).status_code == 422
        assert len(calls) == 2
        detail = [{"loc": ["body", "flag"], "msg": "invalid flag", "type": "value_error"}]
        app.state.tsec_client.transport = httpx.MockTransport(lambda _: httpx.Response(422, json={"detail": detail}))
        response = await client.post("/api/v1/tsec/challenges/submit", json={"unique_code": "web", "flag": "x"})
        assert response.status_code == 422
        assert response.json() == {"detail": detail}
        app.state.tsec_client.transport = httpx.MockTransport(lambda _: httpx.Response(409, json={
            "code": "duplicate", "message": "already submitted", "detail": {}}))
        response = await client.post("/api/v1/tsec/challenges/submit", json={"unique_code": "web", "flag": "x"})
        assert response.status_code == 409 and response.json()["code"] == "duplicate"


async def test_missing_configuration_returns_503(settings):
    settings.tsec_base_url = ""
    settings.tsec_token = ""
    app = FastAPI()
    register_tsec(app, settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://local") as client:
        response = await client.get("/api/v1/tsec/challenges")
    assert response.status_code == 503
    assert response.json()["code"] == "not_configured"


def test_official_environment_variable_names(monkeypatch):
    monkeypatch.setenv("BENCHMARK_BASE_URL", "https://benchmark.test")
    monkeypatch.setenv("BENCHMARK_TOKEN", TOKEN)
    settings = Settings(_env_file=None)
    assert settings.tsec_base_url == "https://benchmark.test"
    assert settings.tsec_token == TOKEN
    assert TOKEN not in repr(settings)
    assert TOKEN not in settings.model_dump_json()


async def test_registered_in_real_app_and_cross_origin_protection(settings):
    from security_agent.api import create_app

    settings.tsec_base_url = "https://benchmark.test"
    settings.tsec_token = TOKEN
    app = create_app(settings)
    app.state.tsec_client.transport = httpx.MockTransport(lambda _: httpx.Response(200, json=[]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1") as client:
        assert (await client.get("/api/v1/tsec/challenges")).json() == []
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert len([path for path in paths if path.startswith("/api/v1/tsec/")]) == 5
        for method, action in [("POST", "start"), ("GET", "hint"), ("POST", "close")]:
            response = await client.request(method, f"/api/v1/tsec/challenges/{action}",
                                            params={"unique_code": "web"}, headers={"Origin": "https://elsewhere.test"})
            assert response.status_code == 403
