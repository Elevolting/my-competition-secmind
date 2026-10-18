from __future__ import annotations

from fastapi.testclient import TestClient

from security_agent.api import create_app
from security_agent.asset_graph import project_asset_graph
from security_agent.schemas import AgentState, InputArtifact, RunStatus, TaskRequest, ToolResult, ToolStatus


def test_asset_graph_uses_explicit_scoped_records_only() -> None:
    state = AgentState(
        run_id="asset-test",
        task=TaskRequest(objective="Inspect authorized fixture", target_scope=["https://lab.test/app"]),
        input_artifacts=[InputArtifact(original_name="sample.txt", relative_path="sample.txt",
                                       sha256="a" * 64, size_bytes=1)],
        observations=[ToolResult(status=ToolStatus.SUCCESS, data={"coverage": {
            "endpoints": ["https://lab.test/app/login", "https://other.test/admin"],
        }})],
    )
    graph = project_asset_graph(state)
    nodes = {item["id"]: item for item in graph["nodes"]}
    assert "endpoint:https://lab.test/app/login" in nodes
    assert nodes["endpoint:https://lab.test/app/login"]["status"] == "discovered"
    assert not any("other.test" in key for key in nodes)
    assert any(item["type"] == "artifact" and item["sha256"] == "a" * 64 for item in nodes.values())
    assert any(item["type"] == "artifact" and item["status"] == "input" for item in nodes.values())
    assert graph["sources"] == {"scope": 1, "tool": 1, "artifact": 1, "invocation": 0}


def test_asset_graph_ignores_non_network_scope_markers() -> None:
    state = AgentState(
        run_id="marker-test",
        task=TaskRequest(
            objective="Inspect a local fixture",
            target_scope=["uploaded-source", "registered-benchmark:fixture-1", "127.0.0.1:8001"],
        ),
    )
    graph = project_asset_graph(state)
    ids = {item["id"] for item in graph["nodes"]}
    assert "host:127.0.0.1" in ids
    assert "service:http://127.0.0.1:8001" in ids
    assert not any("uploaded-source" in item or "registered-benchmark" in item for item in ids)


def test_asset_graph_preserves_observation_provenance_and_ignores_failed_coverage() -> None:
    state = AgentState(
        run_id="provenance-test",
        task=TaskRequest(objective="Inspect local target", target_scope=["http://127.0.0.1:8001/app"]),
        observations=[
            ToolResult(status=ToolStatus.ERROR, data={"coverage": {
                "endpoints": ["http://127.0.0.1:8001/app/failed"]}}),
            ToolResult(status=ToolStatus.SUCCESS, data={"call_id": "call-1", "coverage": {
                "confidence": 0.8, "endpoints": ["http://127.0.0.1:8001/app/health"]}}),
        ],
    )
    graph = project_asset_graph(state)
    nodes = {item["id"]: item for item in graph["nodes"]}
    endpoint = nodes["endpoint:http://127.0.0.1:8001/app/health"]
    assert endpoint["provenance"] == [{"source": "tool", "ref": "call-1",
                                       "confidence": 0.8, "observed_at": None}]
    assert not any("failed" in key for key in nodes)
    assert graph["stats"]["coverage_observation_count"] == 1
    assert any(edge["provenance"][0]["ref"] == "call-1" for edge in graph["edges"])


def test_blackboard_mcp_coverage_receipts_are_projected_once_and_bound_to_scope() -> None:
    state = AgentState(
        run_id="mcp-coverage",
        task=TaskRequest(objective="Inspect fixture", target_scope=["https://lab.test/app"]),
    )
    receipts = [
        {"run_id": state.run_id, "call_id": "call-1", "status": "completed",
         "completed_at": "2026-10-05T00:00:00Z", "result": {"structuredContent": {
             "coverage": {"confidence": 0.9, "endpoints": [
                 "https://lab.test/app/login", "https://elsewhere.test/admin",
             ]}}}},
        {"run_id": state.run_id, "call_id": "call-1", "status": "completed",
         "result": {"structuredContent": {"coverage": {"endpoints": ["https://lab.test/app/duplicate"]}}}},
        {"run_id": state.run_id, "call_id": "call-2", "status": "failed",
         "result": {"structuredContent": {"coverage": {"endpoints": ["https://lab.test/app/failed"]}}}},
        {"run_id": "another-run", "call_id": "call-3", "status": "completed",
         "result": {"structuredContent": {"coverage": {"endpoints": ["https://lab.test/app/other"]}}}},
    ]
    graph = project_asset_graph(state, receipts)
    nodes = {item["id"]: item for item in graph["nodes"]}
    endpoint = nodes["endpoint:https://lab.test/app/login"]
    assert endpoint["status"] == "discovered"
    assert endpoint["provenance"][0] == {
        "source": "tool", "ref": "call-1", "confidence": 0.9,
        "observed_at": "2026-10-05T00:00:00Z",
    }
    assert graph["stats"]["coverage_observation_count"] == 1
    assert not any(token in key for key in nodes for token in ("elsewhere", "duplicate", "failed", "other"))


def test_successful_mcp_target_is_invoked_without_claiming_discovery() -> None:
    state = AgentState(run_id="called-target", task=TaskRequest(
        objective="Inspect fixture", target_scope=["https://lab.test/app"],
    ))
    graph = project_asset_graph(state, [{
        "run_id": state.run_id, "call_id": "call-1", "status": "completed",
        "completed_at": "2026-10-05T00:00:00Z",
        "arguments": {"url": "https://lab.test/app/login"},
        "result": {"content": [{"type": "text", "text": "HTTP 200"}]},
    }])
    nodes = {item["id"]: item for item in graph["nodes"]}
    assert nodes["endpoint:https://lab.test/app/login"]["status"] == "invoked"
    assert graph["sources"]["invocation"] == 1
    assert graph["stats"]["discovered_asset_count"] == 0
    assert graph["stats"]["coverage_observation_count"] == 0


def test_http1_mcp_target_is_projected_from_connection_and_request_line() -> None:
    state = AgentState(run_id="http1", task=TaskRequest(
        objective="Inspect fixture", target_scope=["http://127.0.0.1:3000/app"],
    ))
    graph = project_asset_graph(state, [{
        "run_id": state.run_id, "call_id": "call-2", "status": "completed",
        "arguments": {"targetHostname": "127.0.0.1", "targetPort": 3000,
                      "usesHttps": False,
                      "content": "GET /app/login HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n"},
        "result": {"content": [{"type": "text", "text": "HTTP 200"}]},
    }])
    nodes = {item["id"]: item for item in graph["nodes"]}
    assert nodes["endpoint:http://127.0.0.1:3000/app/login"]["status"] == "invoked"


def test_normal_task_blackboard_and_asset_graph_routes(settings) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    state = AgentState(
        run_id="graph-test",
        status=RunStatus.COMPLETED,
        task=TaskRequest(objective="Inspect local fixture", target_scope=["https://lab.test/app"]),
        external_execution={"blackboard": {
            "backend": "local", "project_id": "local:graph-test", "status": "completed",
            "graph": {"title": "sec-task-graph-test", "status": "completed",
                      "facts": [{"id": "origin", "description": "Inspect local fixture"},
                                {"id": "goal", "description": "Verified report"}],
                      "intents": [{"id": "i001", "from": ["origin"], "to": "goal",
                                   "worker": "unified-workbench:graph-test",
                                   "description": "Verified report", "concluded_at": "2026-10-04T00:00:00Z"}]},
        }},
    )
    app.state.service.ledger.save_state(state)
    client = TestClient(app)
    graph = client.get("/api/v1/runs/graph-test/blackboard-graph")
    assert graph.status_code == 200
    assert graph.json()["linked"] is True
    assert any(node["id"] == "fact:goal" for node in graph.json()["nodes"])
    assets = client.get("/api/v1/runs/graph-test/asset-graph")
    assert assets.status_code == 200
    assert any(node["type"] == "endpoint" for node in assets.json()["nodes"])
