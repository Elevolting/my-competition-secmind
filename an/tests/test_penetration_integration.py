from __future__ import annotations

import httpx
import pytest

from security_agent.penetration_integration import (
    assess_project_facts,
    evaluate_project_completion,
    fact_assessment,
    normalize_penetration_graph,
    penetration_get,
    wait_for_project_terminal,
)


@pytest.mark.parametrize("description,severity", [
    ("已确认目录遍历漏洞，成功读取敏感文件内容。", "HIGH"),
    ("Confirmed path traversal (LFI). Confirmed payload returned flag.txt contents. Failed attempts were blocked.", "HIGH"),
    ("发现 /login 存在 SQL 注入漏洞", "UNKNOWN"),
    ("Verified limited impact via local file inclusion", "MEDIUM"),
])
def test_fact_assessment_uses_success_and_impact(description, severity):
    assessment = fact_assessment(description)
    assert assessment["type"] == "vulnerability"
    assert assessment["severity"] == severity


@pytest.mark.parametrize("description", [
    "怀疑存在 path traversal，尚未验证",
    "仅尝试 LFI，请求被拒绝",
    "No confirmed arbitrary file read; request blocked",
])
def test_unverified_fact_does_not_become_vulnerability(description):
    assessment = fact_assessment(description)
    assert assessment["type"] == "fact"
    assert assessment["severity"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_semantic_assessment_is_cached_and_requires_literal_evidence():
    class Gateway:
        calls = 0

        async def structured(self, **kwargs):
            self.calls += 1
            from security_agent.penetration_integration import ModelFactAssessment
            return ModelFactAssessment(vulnerability=True, severity="MEDIUM",
                reason="confirmed limited impact", evidence_quote="server returned the secret"), None

    detail = {"facts": [{"id": "f1", "description": "server returned the secret"}]}
    gateway, cache = Gateway(), {}
    await assess_project_facts(detail, cache, gateway, model_budget=1)
    await assess_project_facts(detail, cache, gateway, model_budget=1)
    assert gateway.calls == 1
    assert cache["f1"]["type"] == "vulnerability"
    detail["facts"][0]["description"] = "server may accept the payload"
    await assess_project_facts(detail, cache, gateway, model_budget=1)
    assert gateway.calls == 2
    assert cache["f1"]["type"] == "fact"


@pytest.mark.asyncio
async def test_runtime_status_reads_ignore_ambient_proxy_configuration(monkeypatch):
    captured = {}
    original = httpx.AsyncClient
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json=[]))

    class RecordingClient(original):
        def __init__(self, *args, **kwargs):
            captured.update(kwargs)
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("security_agent.penetration_integration.httpx.AsyncClient", RecordingClient)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    result = await penetration_get("http://127.0.0.1:8000", "/projects", 1)
    assert result == []
    assert captured["trust_env"] is False


@pytest.mark.asyncio
async def test_unavailable_semantic_model_falls_back_to_unknown():
    class Gateway:
        async def structured(self, **kwargs):
            raise RuntimeError("model unavailable")

    cache = await assess_project_facts(
        {"facts": [{"id": "f1", "description": "An unusual condition was observed"}]},
        {}, Gateway(), model_budget=1)
    assert cache["f1"]["type"] == "fact"
    assert cache["f1"]["severity"] == "UNKNOWN"


def test_normalize_penetration_graph_preserves_ai_fact_intent_semantics() -> None:
    graph = normalize_penetration_graph(
        {
            "project": {
                "id": "proj_001",
                "title": "authorized lab",
                "status": "active",
                "bootstrap_enabled": True,
                "created_at": "2026-08-28T00:00:00Z",
                "reason": None,
            },
            "facts": [
                {"id": "origin", "description": "测试授权靶场 https://lab.test"},
                {"id": "goal", "description": "确认高风险漏洞"},
                {"id": "f001", "description": "发现 /login 存在 SQL 注入漏洞"},
                {"id": "f002", "description": "服务端使用 Spring Boot"},
            ],
            "intents": [
                {
                    "id": "i001",
                    "from": ["origin"],
                    "to": "f001",
                    "description": "验证登录参数是否可注入",
                    "creator": "ai-worker-1",
                    "worker": "ai-worker-1",
                    "created_at": "2026-08-28T00:00:01Z",
                    "concluded_at": "2026-08-28T00:00:05Z",
                },
                {
                    "id": "i002",
                    "from": ["f001"],
                    "to": None,
                    "description": "猜测可进一步绕过认证",
                    "creator": "ai-worker-1",
                    "worker": None,
                    "created_at": "2026-08-28T00:00:06Z",
                    "concluded_at": None,
                },
                {
                    "id": "i003",
                    "from": ["f002"],
                    "to": None,
                    "description": "检查框架管理端点",
                    "creator": "ai-worker-2",
                    "worker": "ai-worker-2",
                    "created_at": "2026-08-28T00:00:07Z",
                    "concluded_at": None,
                },
            ],
            "hints": [
                {
                    "id": "h001",
                    "content": "测试范围只包含 lab.test",
                    "creator": "operator",
                    "created_at": "2026-08-28T00:00:00Z",
                }
            ],
        }
    )

    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["fact:origin"]["type"] == "origin"
    assert nodes["fact:goal"]["type"] == "goal"
    assert nodes["fact:f001"]["type"] == "fact"
    assert nodes["fact:f001"]["ai_generated"] is True
    assert nodes["fact:f002"]["type"] == "fact"
    assert nodes["intent:i001"]["type"] == "intent"
    assert nodes["intent:i001"]["status"] == "completed"
    assert nodes["intent:i002"]["type"] == "hypothesis"
    assert nodes["intent:i002"]["status"] == "waiting"
    assert nodes["intent:i003"]["type"] == "intent"
    assert nodes["intent:i003"]["status"] == "running"
    assert nodes["hint:h001"]["ai_generated"] is False
    assert not any(node["id"].startswith("worker:") for node in nodes.values())
    assert nodes["intent:i003"]["worker"] == "ai-worker-2"

    edges = {(edge["source"], edge["target"], edge["type"]) for edge in graph["edges"]}
    assert ("fact:origin", "intent:i001", "intent-chain") in edges
    assert ("intent:i001", "fact:f001", "produces") in edges
    assert not any("worker:" in source or "worker:" in target for source, target, _ in edges)
    assert ("fact:f001", "intent:i002", "hypothesis") in edges
    assert graph["counts"].get("vulnerability", 0) == 0
    assert graph["counts"].get("worker", 0) == 0


def test_completed_goal_report_is_projected_as_conclusion() -> None:
    graph = normalize_penetration_graph({
        "project": {"id": "p1", "title": "test", "status": "completed"},
        "facts": [{"id": "origin", "description": "uploaded material"},
                  {"id": "goal", "description": "analyze the material"}],
        "intents": [{"id": "i-final", "from": ["origin"], "to": "goal",
                     "description": "日志分析完成，共发现 3 个安全事件。",
                     "creator": "unified-workbench:run-1", "worker": "unified-workbench:run-1",
                     "concluded_at": "2026-10-11T08:09:05Z"}],
        "hints": [],
    })

    node = next(item for item in graph["nodes"] if item["id"] == "intent:i-final")
    assert node["type"] == "conclusion"
    assert node["ai_generated"] is False
    assert node["creator"] == "报告摘要"


@pytest.mark.parametrize('description', [
    '工具拒绝：目标不在授权范围，未确认 SQL 注入漏洞',
    '目标不可达，无法验证高风险漏洞',
    'Tool rejected the target as out of scope; no confirmed RCE',
    '未发现漏洞，扫描结果为空',
])
def test_negative_penetration_facts_are_not_confirmed_vulnerabilities(description):
    graph = normalize_penetration_graph({
        'project': {'id': 'p1', 'title': 'test', 'status': 'active'},
        'facts': [{'id': 'f1', 'description': description}], 'intents': [], 'hints': [],
    })
    assert next(node for node in graph['nodes'] if node['id'] == 'fact:f1')['type'] == 'fact'
    assert graph['counts'].get('vulnerability', 0) == 0


def _detail(status: str, *, goal: bool = False) -> dict:
    intents = [{"id": "i1", "from": ["origin"], "to": "goal", "concluded_at": "now"}] if goal else []
    return {"project": {"id": "proj-1", "status": status}, "facts": [], "intents": intents, "hints": []}


def test_project_completed_requires_concluded_goal_intent() -> None:
    assert evaluate_project_completion(_detail("completed"))["objective_reached"] is False
    decision = evaluate_project_completion(_detail("completed", goal=True))
    assert decision["terminal"] is True
    assert decision["objective_reached"] is True


@pytest.mark.asyncio
async def test_wait_for_project_terminal_polls_until_delayed_completion(monkeypatch) -> None:
    responses = iter([_detail("running"), _detail("running"), _detail("completed", goal=True)])

    async def fake_get(_base_url, _path, _timeout=None, **_kwargs):
        return next(responses)

    updates = []
    monkeypatch.setattr("security_agent.penetration_integration.penetration_get", fake_get)
    result = await wait_for_project_terminal(
        "http://security_runtime.test",
        "proj-1",
        timeout_seconds=1,
        interval_seconds=0.01,
        on_update=updates.append,
    )
    assert result["status"] == "completed"
    assert result["objective_reached"] is True
    assert len(updates) == 3


@pytest.mark.asyncio
async def test_wait_for_project_terminal_retries_transient_poll_errors(monkeypatch) -> None:
    responses = iter([RuntimeError("temporary"), _detail("completed", goal=True)])

    async def fake_get(_base_url, _path, _timeout=None, **_kwargs):
        item = next(responses)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr("security_agent.penetration_integration.penetration_get", fake_get)
    result = await wait_for_project_terminal("http://security_runtime.test", "proj-1", timeout_seconds=1, interval_seconds=0.01)
    assert result["status"] == "completed"
    assert result["objective_reached"] is True


@pytest.mark.asyncio
async def test_wait_for_project_terminal_times_out_without_false_success(monkeypatch) -> None:
    stopped = []

    async def fake_get(_base_url, _path, _timeout=None, **_kwargs):
        return _detail("running")

    async def fake_update(_base_url, project_id, status, _timeout=None, **_kwargs):
        stopped.append((project_id, status))
        return {"id": project_id, "status": status}

    monkeypatch.setattr("security_agent.penetration_integration.penetration_get", fake_get)
    monkeypatch.setattr("security_agent.penetration_integration.penetration_update_status", fake_update)
    result = await wait_for_project_terminal("http://security_runtime.test", "proj-1", timeout_seconds=0.02, interval_seconds=0.01)
    assert result["status"] == "timeout"
    assert result["objective_reached"] is False
    assert result["terminal"] is True
    assert result["external_stop_requested"] is True
    assert stopped == [("proj-1", "stopped")]


def test_stopped_project_is_a_terminal_failure() -> None:
    decision = evaluate_project_completion(_detail("stopped"))
    assert decision["terminal"] is True
    assert decision["failed"] is True
    assert decision["objective_reached"] is False
