from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secmind.schemas import RiskLevel, Scenario, ToolContext, ToolManifest, ToolResult, ToolStatus
from secmind.tools import (
    BanditTool,
    BaseTool,
    JavaSemanticSastTool,
    ProjectInventoryTool,
    PythonDataflowTool,
    ReversePeAnalysisTool,
    SecretPatternTool,
    ToolError,
    ToolRegistry,
    default_registry,
    normalize_bandit_findings,
)


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


@pytest.mark.asyncio
async def test_bandit_never_imports_module_from_uploaded_workspace(tmp_path: Path) -> None:
    marker = tmp_path / "module_executed"
    (tmp_path / "bandit.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    (tmp_path / "sample.py").write_text("import subprocess\nsubprocess.Popen('x', shell=True)\n", encoding="utf-8")
    result = await BanditTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )
    assert result.status == ToolStatus.SUCCESS
    assert not marker.exists()


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


async def test_inventory_and_secret_scan_are_deterministic_and_redacted(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("fastapi==1.0\n", encoding="utf-8")
    (workspace / "settings.py").write_text('API_KEY = "super-secret-value"\n', encoding="utf-8")
    context = ToolContext(
        run_id="run",
        step_id="inventory",
        workspace=str(workspace),
        allowed_paths=[str(workspace)],
    )
    inventory = await ProjectInventoryTool().invoke({"target": "."}, context)
    assert inventory.status == ToolStatus.SUCCESS
    assert inventory.data["languages"] == {"python": 1}
    assert inventory.data["dependency_files"] == ["requirements.txt"]

    secrets_result = await SecretPatternTool().invoke({"target": "."}, context)
    assert secrets_result.status == ToolStatus.SUCCESS
    assert len(secrets_result.data["findings"]) == 1
    assert secrets_result.data["findings"][0]["rule_id"] == "CWE-798"
    assert secrets_result.data["findings"][0]["raw"]["native_rule_id"] == "SECMIND-SECRET-001"
    assert secrets_result.evidence[0].metadata["weakness_ids"] == ["CWE-798"]
    rendered = secrets_result.model_dump_json()
    assert "super-secret-value" not in rendered
    assert "redacted" in rendered.lower()


@pytest.mark.asyncio
async def test_inventory_is_language_agnostic_and_recognizes_config_sources(tmp_path: Path) -> None:
    (tmp_path / "api.yaml").write_text("openapi: 3.0.0\n", encoding="utf-8")
    (tmp_path / "policy.json").write_text('{"enabled": true}\n', encoding="utf-8")
    tool = ProjectInventoryTool()

    result = await tool.invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="inventory", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert tool.manifest.supported_languages == []
    assert result.status == ToolStatus.SUCCESS
    assert result.data["languages"] == {"json": 1, "yaml": 1}


class SchemaTool(BaseTool):
    def __init__(self, name: str = "schema", schema: dict[str, Any] | None = None) -> None:
        self.manifest = ToolManifest(
            name=name,
            version="1",
            description="schema test",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema=schema or {},
            output_schema={},
            risk_level=RiskLevel.R0,
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        return ToolResult(status=ToolStatus.SUCCESS)


def test_registry_rejects_duplicates_invalid_schemas_and_unknown_tools() -> None:
    registry = ToolRegistry()
    registry.register(SchemaTool())
    with pytest.raises(ToolError, match="Duplicate"):
        registry.register(SchemaTool())
    with pytest.raises(ToolError, match="Invalid JSON Schema"):
        registry.register(SchemaTool("bad-schema", {"type": "not-a-json-type"}))
    with pytest.raises(ToolError, match="Unknown tool"):
        registry.get("missing")
    assert registry.manifests()[0].name == "schema"


def test_bandit_normalizer_has_stable_evidence_and_remediation() -> None:
    raw = [
        {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "filename": "app.py",
            "line_number": 2,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "shell=True",
            "secret_value": "must-not-be-copied",
        }
    ]
    evidence, findings = normalize_bandit_findings(raw, "1")
    assert evidence[0].metadata["test_id"] == "B602"
    assert evidence[0].metadata["native_rule_id"] == "B602"
    assert evidence[0].metadata["normalized_rule_id"] == "CWE-78"
    assert evidence[0].metadata["weakness_ids"] == ["CWE-78"]
    assert evidence[0].metadata["assurance_level"] == "integrity_verified"
    assert findings[0]["rule_id"] == "CWE-78"
    assert findings[0]["raw"]["test_id"] == "B602"
    assert findings[0]["raw"]["native_rule_id"] == "B602"
    assert findings[0]["raw"]["weakness_ids"] == ["CWE-78"]
    assert findings[0]["remediation"]
    assert "secret_value" not in findings[0]["raw"]


def test_bandit_import_blacklist_is_context_not_a_standalone_finding() -> None:
    evidence, findings = normalize_bandit_findings(
        [
            {
                "test_id": "B406",
                "test_name": "blacklist",
                "filename": "app.py",
                "line_number": 1,
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "issue_text": "import xml.sax",
            }
        ],
        "1",
    )
    assert evidence == []
    assert findings == []


def test_bandit_uses_scanner_cwe_for_unlisted_native_rule_and_drops_unmapped_rule() -> None:
    evidence, findings = normalize_bandit_findings(
        [
            {
                "test_id": "B999",
                "issue_cwe": {"id": 918},
                "filename": "app.py",
                "line_number": 1,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "untrusted URL reaches a request sink",
            },
            {
                "test_id": "B998",
                "filename": "app.py",
                "line_number": 2,
                "issue_severity": "LOW",
                "issue_confidence": "LOW",
                "issue_text": "no weakness identity",
            },
        ],
        "1",
    )

    assert [item["rule_id"] for item in findings] == ["CWE-918"]
    assert evidence[0].metadata["native_rule_id"] == "B999"
    assert evidence[0].metadata["weakness_ids"] == ["CWE-918"]


@pytest.mark.asyncio
async def test_python_dataflow_emits_cwe_and_semantic_flow_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import requests\n\ndef fetch(user_url):\n    target = user_url\n    return requests.get(target)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert [item["rule_id"] for item in result.data["findings"]] == ["CWE-918"]
    assert result.data["findings"][0]["raw"]["data_flow"] == ["parameter:user_url", "sink:requests.get"]
    assert result.evidence[0].metadata["assurance_level"] == "semantically_corroborated"
    assert result.evidence[0].metadata["evidence_type"] == "sast_flow"


@pytest.mark.asyncio
async def test_python_dataflow_does_not_publish_generic_url_wrapper_as_ssrf(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n\ndef fetch(url):\n    return requests.get(url, timeout=5)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"] == []


@pytest.mark.asyncio
async def test_python_dataflow_keeps_explicit_input_source_as_ssrf(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n\ndef fetch():\n    target = input()\n    return requests.get(target)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"][0]["rule_id"] == "CWE-918"
    assert result.data["findings"][0]["raw"]["data_flow"] == ["source:input", "sink:requests.get"]


@pytest.mark.asyncio
async def test_python_dataflow_finds_tainted_django_raw_query(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def login(request):\n"
        "    name = request.POST.get('name')\n"
        '    query = "SELECT * FROM users WHERE name=\'" + name + "\'"\n'
        "    return User.objects.raw(query)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"][0]["rule_id"] == "CWE-89"
    assert result.data["findings"][0]["raw"]["native_rule_id"] == "PYFLOW-DJANGO-RAW-SQL-001"


@pytest.mark.asyncio
async def test_python_dataflow_follows_local_urlopen_wrapper_parameter(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "def _urlopen(urlopen_func, untrusted_url):\n"
        "    return urlopen_func(untrusted_url)\n\n"
        "def fetch(user_url):\n"
        "    return _urlopen(urlopen, user_url)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert [item["rule_id"] for item in result.data["findings"]] == ["CWE-918"]
    assert result.data["findings"][0]["raw"]["native_rule_id"] == "PYFLOW-SSRF-001"


@pytest.mark.asyncio
async def test_python_dataflow_uses_url_argument_for_generic_request_callables(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "def safe_method_choice(request_method, user_method):\n"
        "    return request_method(user_method, '/fixed')\n\n"
        "def unsafe_url(request_method, user_url):\n"
        "    return request_method('GET', user_url)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert len(result.data["findings"]) == 1
    assert result.data["findings"][0]["raw"]["data_flow"] == [
        "parameter:user_url",
        "sink:request_method",
    ]


@pytest.mark.asyncio
async def test_python_dataflow_uses_second_argument_for_requests_request(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n\n"
        "def send(user_method, user_url):\n"
        "    requests.request(user_method, '/fixed')\n"
        "    return requests.request('GET', user_url)\n",
        encoding="utf-8",
    )
    result = await PythonDataflowTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="flow", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert len(result.data["findings"]) == 1
    assert result.data["findings"][0]["raw"]["data_flow"] == [
        "parameter:user_url",
        "sink:requests.request",
    ]


@pytest.mark.asyncio
async def test_reverse_pe_analysis_tool_parses_sample_pe(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]  # noqa: ASYNC240 - test fixture setup is bounded
    sample = repo_root / "reverse_evaluation" / "fixtures" / "safe-demo-v1" / "build" / "reverse_demo.exe"
    copied = tmp_path / "sample.exe"
    copied.write_bytes(sample.read_bytes())

    result = await ReversePeAnalysisTool().invoke(
        {"target": "."},
        ToolContext(run_id="run", step_id="reverse", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["file"]["architecture"] == "x86-64"
    assert result.data["pe"]["entrypoint_rva"] == "0x14e0"
    assert result.data["pe"]["section_count"] >= 1
    api_names = {item["api"] for item in result.data["import_hints"]}
    assert {"fopen", "strcmp"} <= api_names


@pytest.mark.asyncio
async def test_builtin_tools_deny_missing_or_out_of_scope_targets(tmp_path: Path) -> None:
    context = ToolContext(run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)])
    for tool in (
        BanditTool(),
        PythonDataflowTool(),
        JavaSemanticSastTool(),
        ProjectInventoryTool(),
        SecretPatternTool(),
    ):
        result = await tool.invoke({"target": "missing"}, context)
        assert result.status == ToolStatus.DENIED
        assert result.error_code == "TOOL_SCOPE_VIOLATION"


def test_default_registry_exposes_all_declared_tools() -> None:
    names = {manifest.name for manifest in default_registry().manifests()}
    assert {
        "project_inventory",
        "bandit_python_audit",
        "python_taint_audit",
        "java_semantic_sast",
        "pe_reverse_analysis",
        "secret_pattern_scan",
        "semgrep_sast",
    } <= names
