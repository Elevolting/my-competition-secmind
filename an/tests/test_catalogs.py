from pathlib import Path

from security_agent.mcp_catalog import MCPCatalog
from security_agent.prompt_catalog import PromptCatalog
from security_agent.tools import default_registry


def test_prompt_catalog_is_read_only_and_complete() -> None:
    catalog = PromptCatalog()
    entries = catalog.list_metadata()
    assert len(entries) == 6
    assert {item["key"] for item in entries} >= {"primary_agent", "pentester", "reporter"}
    assert all(item["runtime_injected"] is False for item in entries)
    assert all(len(str(item["checksum"])) == 64 for item in entries)


def test_mcp_catalog_never_enables_or_connects(tmp_path: Path) -> None:
    catalog = MCPCatalog(
        Path(__file__).parents[1] / "config" / "mcp-servers.json",
        storage_path=tmp_path / "mcp-catalog.json",
    )
    payload = catalog.payload()
    assert payload["runtime_enabled"] is False
    assert payload["invocation_enabled"] is False
    assert payload["tool_registration"] == "not_registered"
    assert payload["candidate_count"] == 3
    assert payload["safe_tool_count"] == 32
    assert set(payload["excluded_servers"]) == {"local-http-fetch", "local-chrome-devtools"}
    assert all(item["enabled"] is False for item in payload["servers"])
    assert all(item["safe_server"] is True for item in payload["servers"])
    assert all(item["icon"] for item in payload["servers"])
    assert all(tool["display_name"] and tool["icon"] for server in payload["servers"] for tool in server["tools"])
    assert all(item["runtime_exposed"] is False for server in payload["servers"] for item in server["tools"])
    assert all(not item.name.startswith("mcp:") for item in default_registry().manifests())


def test_mcp_catalog_crud_remains_presentation_only(tmp_path: Path) -> None:
    catalog = MCPCatalog(
        Path(__file__).parents[1] / "config" / "mcp-servers.json",
        storage_path=tmp_path / "mcp-catalog.json",
    )
    server = catalog.create_server(
        {
            "server_id": "demo-server",
            "name": "Demo Server",
            "purpose": "仅用于界面展示",
            "category": "demo",
            "transport": "display_only",
            "url": "",
            "icon": "safety",
        }
    )
    assert server["enabled"] is False
    assert server["displayable"] is True
    tool = catalog.create_tool(
        "demo-server",
        {
            "name": "demo_tool",
            "display_name": "演示工具",
            "purpose": "展示工具详情",
            "input": "演示输入",
            "returns": "演示输出",
            "invocation_timing": "仅在详情页展示",
            "risk_level": "R0",
            "icon": "tool",
        },
    )
    assert tool is not None
    assert tool["runtime_exposed"] is False
    updated = catalog.update_tool(
        "demo-server",
        "demo_tool",
        {
            "display_name": "已编辑的演示工具",
            "purpose": "展示编辑结果",
            "input": "编辑后的输入",
            "returns": "编辑后的输出",
            "invocation_timing": "仍然只用于展示",
            "risk_level": "R1",
            "icon": "experiment",
        },
    )
    assert updated is not None
    assert updated["display_name"] == "已编辑的演示工具"
    assert updated["runtime_exposed"] is False
    persisted = MCPCatalog(
        Path(__file__).parents[1] / "config" / "mcp-servers.json",
        storage_path=tmp_path / "mcp-catalog.json",
    ).payload()
    assert persisted["runtime_enabled"] is False
    assert persisted["invocation_enabled"] is False
    assert {item["server_id"] for item in persisted["servers"]} >= {"demo-server"}
    assert catalog.delete_tool("demo-server", "demo_tool") is True
    assert catalog.delete_server("demo-server") is True
    assert catalog.get_server("demo-server") is None
