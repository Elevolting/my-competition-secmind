from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from secmind.config import Settings
from secmind.guardrail import Guardrail
from secmind.runtime import _runtime_allowlist, reviewed_semgrep_rules_path
from secmind.sandbox import SandboxToolSpec
from secmind.schemas import ToolContext, ToolStatus
from secmind.tools import (
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    DevelopmentSemgrepTool,
    SandboxJsonTool,
    ToolBroker,
    default_registry,
    external_audit_manifests,
)


@pytest.mark.asyncio
async def test_development_semgrep_executes_reviewed_bundle_through_tool_contract(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "import flask\nimport subprocess\n"
        "def route():\n"
        "    value = flask.request.args.get('cmd')\n"
        "    return subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    rules = Path(__file__).parents[1] / "docker" / "tools" / "semgrep" / "rules" / "reviewed"
    tool = DevelopmentSemgrepTool(rules)
    broker = ToolBroker(default_registry(external_tools=[tool]), Guardrail())
    result = await broker.execute(
        "semgrep_sast",
        {"target": "."},
        ToolContext(run_id="run", step_id="semgrep", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"][0]["rule_id"] == "CWE-78"
    assert result.data["findings"][0]["path"] == "app.py"
    assert result.evidence[0].sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "source"),
    [
        (
            "app.js",
            "const fs = require('fs');\nfunction read(req, res) { return fs.readFile(req.query.path, cb); }\n",
        ),
        (
            "app.ts",
            "import * as fs from 'fs';\n"
            "function read(req: any, res: any) { return fs.readFile(req.query.path, cb); }\n",
        ),
        (
            "App.java",
            "import javax.servlet.http.HttpServletRequest;\n"
            "class App { void run(HttpServletRequest request) throws Exception {\n"
            '  String command = request.getParameter("cmd");\n'
            "  Runtime.getRuntime().exec(command);\n"
            "} }\n",
        ),
    ],
)
async def test_development_semgrep_reaches_reviewed_javascript_typescript_and_java_rules(
    tmp_path: Path, filename: str, source: str
) -> None:
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    rules = Path(__file__).parents[1] / "docker" / "tools" / "semgrep" / "rules" / "reviewed"
    tool = DevelopmentSemgrepTool(rules)
    broker = ToolBroker(default_registry(external_tools=[tool]), Guardrail())

    result = await broker.execute(
        "semgrep_sast",
        {"target": "."},
        ToolContext(run_id="run", step_id="semgrep", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["findings"]
    assert all(item["path"] == filename for item in result.data["findings"])
    expected_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    assert all(item["line"] >= 1 for item in result.data["findings"])
    assert all(item.metadata["file_sha256"] == expected_sha256 for item in result.evidence)


def _adapter() -> ModuleType:
    path = Path(__file__).parents[1] / "docker" / "tools" / "semgrep" / "run.py"
    spec = importlib.util.spec_from_file_location("secmind_semgrep_adapter", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reviewed_rule_bundle_digest_matches_the_approved_identity() -> None:
    root = Path(__file__).parents[1] / "docker" / "tools" / "semgrep" / "rules" / "reviewed"
    digest = hashlib.sha256()
    rule_files = sorted(path for path in root.rglob("*") if path.is_file())
    assert rule_files
    for path in rule_files:
        relative = path.relative_to(root).as_posix()
        file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(f"{relative}\0{file_digest}\n".encode())

    assert digest.hexdigest() == SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST


def test_reviewed_rule_bundle_resolves_for_runtime_installation() -> None:
    rules = reviewed_semgrep_rules_path()

    assert rules.is_dir()
    assert sorted(item.suffix for item in rules.iterdir()) == [".yml", ".yml", ".yml"]


def test_semgrep_adapter_binds_path_line_sha_and_rule_identity(tmp_path: Path) -> None:
    adapter = _adapter()
    source = tmp_path / "app.py"
    source.write_text("first\nsecond\n", encoding="utf-8")
    adapter.INPUT = tmp_path
    body = {
        "results": [
            {
                "check_id": "secmind.python.flask-shell-command-injection",
                "path": "/input/app.py",
                "start": {"line": 2},
                "extra": {
                    "severity": "ERROR",
                    "message": "shell injection",
                    "metadata": {"cwe": "CWE-78", "remediation": "Use an argument list."},
                },
            }
        ]
    }

    findings, rejected = adapter.normalize_semgrep(body)

    assert rejected == 0
    assert findings[0]["rule_id"] == "CWE-78"
    assert findings[0]["native_rule_id"] == "secmind.python.flask-shell-command-injection"
    assert findings[0]["weakness_ids"] == ["CWE-78"]
    assert findings[0]["file_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_semgrep_adapter_rejects_unbound_path_and_line(tmp_path: Path) -> None:
    adapter = _adapter()
    (tmp_path / "app.py").write_text("one\n", encoding="utf-8")
    adapter.INPUT = tmp_path
    base = {"check_id": "candidate", "extra": {}, "start": {"line": 1}}

    findings, rejected = adapter.normalize_semgrep(
        {"results": [{**base, "path": "/etc/passwd"}, {**base, "path": "/input/app.py", "start": {"line": 2}}]}
    )

    assert findings == []
    assert rejected == 2


def test_semgrep_adapter_hashes_each_input_once_and_fails_on_scan_errors(monkeypatch, tmp_path: Path) -> None:
    adapter = _adapter()
    (tmp_path / "app.py").write_text("one\ntwo\n", encoding="utf-8")
    adapter.INPUT = tmp_path
    original = adapter._file_binding
    calls = 0

    def counted(path: str):
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(adapter, "_file_binding", counted)
    base = {"check_id": "candidate", "path": "/input/app.py", "extra": {"metadata": {}}}
    findings, rejected = adapter.normalize_semgrep(
        {"results": [{**base, "start": {"line": 1}}, {**base, "start": {"line": 2}}], "errors": []}
    )
    assert len(findings) == 2
    assert rejected == 0
    assert calls == 1

    with pytest.raises(ValueError, match="incomplete"):
        adapter.normalize_semgrep({"results": [], "errors": [{"message": "parse failed"}]})


def test_semgrep_candidate_is_not_allowlisted_until_explicitly_enabled(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", "sha256:" + "1" * 64)
    monkeypatch.setenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST)
    disabled = Settings(input_root=tmp_path / "in", run_root=tmp_path / "run", artifact_root=tmp_path / "art")
    enabled = disabled.model_copy(update={"semgrep_candidate_rules_enabled": True})

    assert "semgrep_sast" not in _runtime_allowlist(disabled)
    assert "semgrep_sast" in _runtime_allowlist(enabled)


@pytest.mark.parametrize("configured", [None, "not-a-digest", "0" * 64])
def test_semgrep_enablement_rejects_missing_or_unapproved_rule_bundle(
    monkeypatch,
    tmp_path: Path,
    configured: str | None,
) -> None:
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", "sha256:" + "1" * 64)
    if configured is None:
        monkeypatch.delenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", raising=False)
    else:
        monkeypatch.setenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", configured)
    settings = Settings(
        input_root=tmp_path / "in",
        run_root=tmp_path / "run",
        artifact_root=tmp_path / "art",
        semgrep_candidate_rules_enabled=True,
    )

    with pytest.raises(RuntimeError, match="approved immutable rule bundle"):
        _runtime_allowlist(settings)


def test_semgrep_adapter_rejects_unapproved_manifest_even_if_directly_constructed(monkeypatch) -> None:
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", "sha256:" + "1" * 64)
    monkeypatch.setenv("SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST", "0" * 64)
    spec = SandboxToolSpec(
        name="semgrep_sast",
        image_digest="sha256:" + "1" * 64,
        entrypoint=("/opt/secmind-tools/run-semgrep",),
    )
    manifest = next(item for item in external_audit_manifests({"semgrep_sast": spec}) if item.name == "semgrep_sast")

    with pytest.raises(ValueError, match="approved immutable rule bundle"):
        SandboxJsonTool(manifest, "http://sandbox-runner")
