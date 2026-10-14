from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from security_agent.mcp_generated import GeneratedMCPStore, GeneratedToolProposal
from security_agent.schemas import ToolContext, ToolStatus
from security_agent.tools import BanditTool, PenetrationModuleTool, WorkspaceSecurityAuditTool


@pytest.mark.asyncio
async def test_bandit_tool_produces_evidence(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("import subprocess\nsubprocess.Popen('echo unsafe', shell=True)\n", encoding="utf-8")
    result = await BanditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"]
    assert result.evidence
    assert result.data["findings"][0]["evidence_ids"]
    assert "B602" in {item["rule_id"] for item in result.data["findings"]}
    assert "B404" not in {item["rule_id"] for item in result.data["findings"]}
    assert all(item["path"] == "bad.py" for item in result.data["findings"])
    assert all(item.artifact_ref == "bad.py" and item.sha256 for item in result.evidence)


@pytest.mark.asyncio
async def test_bandit_tool_rejects_scope_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent
    result = await BanditTool().invoke(
        {"target": str(outside)},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )
    assert result.status == ToolStatus.DENIED


@pytest.mark.asyncio
async def test_workspace_audit_reads_java_and_reports_coverage(tmp_path: Path) -> None:
    source = tmp_path / "Main.java"
    source.write_text(
        '@RequestParam String input; runtimeServices.parse(new StringReader(input), "home");',
        encoding="utf-8",
    )
    result = await WorkspaceSecurityAuditTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["coverage"]["scanned_files"] == ["Main.java"]
    assert result.data["findings"][0]["rule_id"] == "AUDIT-JAVA-SSTI"
    assert result.evidence


@pytest.mark.asyncio
async def test_workspace_audit_does_not_claim_success_without_coverage(tmp_path: Path) -> None:
    (tmp_path / "font.ttf").write_bytes(b"\x00\x01binary")
    result = await WorkspaceSecurityAuditTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )
    assert result.status == ToolStatus.ERROR
    assert result.error_code == "NO_AUDIT_COVERAGE"
    assert result.data["coverage"]["scanned_file_count"] == 0


@pytest.mark.asyncio
async def test_workspace_audit_reads_utf8_text_with_opaque_suffix(tmp_path: Path) -> None:
    (tmp_path / "artifact_01.og").write_text("\n", encoding="utf-8")
    (tmp_path / "artifact_02.og").write_text(
        "config interface 'lan'\n option proto 'dhcp'\n",
        encoding="utf-8",
    )
    result = await WorkspaceSecurityAuditTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["coverage"]["scanned_file_count"] == 2
    assert result.data["coverage"]["skipped_file_count"] == 0


@pytest.mark.asyncio
async def test_penetration_adapter_activates_existing_blackboard_project(monkeypatch, tmp_path: Path) -> None:
    captured: list[tuple[str, str]] = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload
            self.status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def fake_urlopen(request, timeout=0):
        captured.append((request.get_method(), request.full_url))
        if request.get_method() == "POST":
            payload = json.loads(request.data.decode())
            assert payload["activation_token"] == "t" * 32
        project = {"id": "proj_test", "title": "sec-task-run", "status": "active",
                   "dispatcher_enabled": request.get_method() == "POST"}
        return FakeResponse({"project": project} if request.get_method() == "GET" else project)

    monkeypatch.setattr("security_agent.tools.urllib.request.urlopen", fake_urlopen)
    result = await PenetrationModuleTool().invoke(
        {"target": "http://target.test"},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            module_base_url="http://penetration.test",
            task_objective="完成授权渗透题并提交 flag",
            target_scope=["http://target.test"],
            external_execution={"blackboard": {"backend": "remote", "project_id": "proj_test", "status": "entered",
                                                "activation_token": "t" * 32}},
        ),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["project_id"] == "proj_test"
    assert captured == [
        ("GET", "http://penetration.test/projects/proj_test"),
        ("POST", "http://penetration.test/projects/proj_test/dispatcher/activate"),
    ]


async def test_penetration_activation_recovers_lost_response(monkeypatch, tmp_path: Path) -> None:
    enabled = False
    calls = []

    class FakeResponse:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def fake_urlopen(request, timeout=0):
        nonlocal enabled
        calls.append(request.get_method())
        if request.get_method() == 'POST':
            enabled = True
            raise urllib.error.URLError('response lost after commit')
        return FakeResponse({'project': {
            'id': 'proj_test', 'title': 'sec-task-run', 'status': 'active',
            'dispatcher_enabled': enabled,
        }})

    monkeypatch.setattr('security_agent.tools.urllib.request.urlopen', fake_urlopen)
    result = await PenetrationModuleTool().invoke({'target': 'http://target.test'}, ToolContext(
        run_id='run', step_id='step', workspace=str(tmp_path), allowed_paths=[str(tmp_path)],
        module_base_url='http://penetration.test',
        external_execution={'blackboard': {'backend': 'remote', 'project_id': 'proj_test', 'status': 'entered',
                                           'activation_token': 't' * 32}},
    ))
    assert result.status == ToolStatus.SUCCESS
    assert calls == ['GET', 'POST', 'GET']


@pytest.mark.asyncio
async def test_workspace_audit_reuses_generated_mcp_adapter(tmp_path: Path) -> None:
    sample = tmp_path / "sample.dat"
    sample.write_bytes(b"HEADER\x00FLAG=demo-value\x00END")
    mcp_root = tmp_path / "mcp"
    GeneratedMCPStore(mcp_root).save(
        GeneratedToolProposal(
            tool_id="dat-strings",
            name="DAT 字符串提取器",
            description="提取未知 DAT 文件中的可打印字符串",
            file_extensions=[".dat"],
            operation="binary_strings",
            rationale="扫描器无法识别 DAT 文件，需要只读字符串提取。",
        ),
        source_run_id="run",
    )
    result = await WorkspaceSecurityAuditTool().invoke(
        {"target": "."},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            mcp_generated_root=str(mcp_root),
        ),
    )
    assert result.status == ToolStatus.SUCCESS
    assert result.data["coverage"]["generated_tools_used"] == ["dat-strings"]
    assert result.evidence[0].source == "generated-mcp:dat-strings"
