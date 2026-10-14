from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from secmind.sandbox import SandboxInputFile, default_allowlist
from secmind.schemas import RiskLevel, Scenario, ToolContext, ToolHealth, ToolManifest, ToolStatus
from secmind.tools import (
    EXTERNAL_TOOL_NAMES,
    SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    SandboxJsonTool,
    ToolValidationError,
    UnavailableTool,
    external_audit_manifests,
)

EXTERNAL_IMAGE_ENV = (
    "SECMIND_SANDBOX_SEMGREP_IMAGE",
    "SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST",
    "SECMIND_SANDBOX_GITLEAKS_IMAGE",
    "SECMIND_SANDBOX_SYFT_IMAGE",
    "SECMIND_SANDBOX_OSV_IMAGE",
)
IMAGE = "sha256:" + ("a" * 64)


def _clear_external_images(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in EXTERNAL_IMAGE_ENV:
        monkeypatch.delenv(name, raising=False)


def _enable_semgrep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", IMAGE)
    monkeypatch.setenv(
        "SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST",
        SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST,
    )


def test_external_tools_are_unavailable_without_immutable_images(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_external_images(monkeypatch)
    allowlist = default_allowlist()
    manifests = external_audit_manifests(allowlist)

    assert not set(EXTERNAL_TOOL_NAMES) & set(allowlist)
    assert all(manifest.health_status == ToolHealth.UNAVAILABLE for manifest in manifests)
    assert all(manifest.execution.image_digest is None for manifest in manifests)


def test_external_allowlist_has_fixed_entrypoint_and_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)

    allowlist = default_allowlist()
    spec = allowlist["semgrep_sast"]
    manifest = next(item for item in external_audit_manifests(allowlist) if item.name == "semgrep_sast")

    assert spec.entrypoint == ("/opt/secmind-tools/run-semgrep",)
    assert manifest.health_status == ToolHealth.HEALTHY
    assert manifest.execution.image_digest == IMAGE
    assert manifest.execution.entrypoint == ["/opt/secmind-tools/run-semgrep"]
    assert manifest.execution.network_policy == "none"


def test_invalid_external_image_digest_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_external_images(monkeypatch)
    monkeypatch.setenv("SECMIND_SANDBOX_OSV_IMAGE", "osv:latest")

    with pytest.raises(ValueError, match="pinned by sha256"):
        default_allowlist()


@pytest.mark.asyncio
async def test_gitleaks_adapter_fully_redacts_untrusted_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _clear_external_images(monkeypatch)
    monkeypatch.setenv("SECMIND_SANDBOX_GITLEAKS_IMAGE", IMAGE)
    manifest = next(
        item for item in external_audit_manifests(default_allowlist()) if item.name == "gitleaks_secret_scan"
    )
    secret = "ghp_this_must_never_escape_the_adapter"  # noqa: S105  # nosec B105

    def handler(request: httpx.Request) -> httpx.Response:
        request_body = json.loads(request.content)
        assert request_body["tool_name"] == "gitleaks_secret_scan"
        assert "image" not in request_body
        assert "command" not in request_body
        assert "host_path" not in request_body
        return httpx.Response(
            200,
            json={
                "invocation_id": "inv-1",
                "status": "success",
                "data": {
                    "findings": [
                        {
                            "rule_id": "github-pat",
                            "severity": "high",
                            "confidence": "high",
                            "path": "source.py",
                            "line": 1,
                            "title": secret,
                            "description": secret,
                            "file_sha256": hashlib.sha256((tmp_path / "source.py").read_bytes()).hexdigest(),
                            "raw": {"secret": secret, "match": secret},
                        }
                    ],
                    "raw_report": secret,
                },
                "summary": secret,
                "logs": {"tail": secret, "sha256": "b" * 64},
                "duration_ms": 3,
            },
        )

    (tmp_path / "source.py").write_text(f"TOKEN = '{secret}'", encoding="utf-8")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tool = SandboxJsonTool(manifest, "http://runner", "service-token", client)
        result = await tool.invoke(
            {"target": "."},
            ToolContext(
                run_id="run-1",
                step_id="secret",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="inv-1",
            ),
        )

    serialized = json.dumps(result.model_dump(mode="json"))
    assert result.status == ToolStatus.SUCCESS
    assert secret not in serialized
    assert result.data.keys() == {"findings", "coverage"}
    assert result.data["coverage"] == {
        "accepted_count": 1,
        "rejected_count": 0,
        "complete": True,
    }
    assert result.data["findings"][0]["rule_id"] == "CWE-798"
    assert result.data["findings"][0]["raw"]["native_rule_id"] == "github-pat"
    assert result.data["findings"][0]["title"] == "Potential hard-coded secret (value redacted)"
    assert result.evidence[0].metadata["redacted"] is True


@pytest.mark.asyncio
async def test_semgrep_adapter_returns_normalized_finding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)
    manifest = next(item for item in external_audit_manifests(default_allowlist()) if item.name == "semgrep_sast")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "invocation_id": "inv-2",
                "status": "success",
                "data": {
                    "findings": [
                        {
                            "rule_id": "python.lang.security.audit.exec-used",
                            "native_rule_id": "python.lang.security.audit.exec-used",
                            "normalized_rule_id": "CWE-95",
                            "weakness_ids": ["CWE-95"],
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "path": "app.py",
                            "line": 2,
                            "title": "Use of exec",
                            "description": "Avoid dynamic execution.",
                            "file_sha256": hashlib.sha256((tmp_path / "app.py").read_bytes()).hexdigest(),
                        }
                    ],
                    "files_scanned": 1,
                },
                "summary": "ignored adapter-owned summary",
                "logs": {"tail": "", "sha256": "c" * 64},
                "duration_ms": 7,
            },
        )

    (tmp_path / "app.py").write_text("x = 1\nexec(x)\n", encoding="utf-8")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tool = SandboxJsonTool(manifest, "http://runner", "service-token", client)
        result = await tool.invoke(
            {"target": "."},
            ToolContext(
                run_id="run-2",
                step_id="sast",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="inv-2",
            ),
        )

    assert result.status == ToolStatus.SUCCESS
    assert result.data["files_scanned"] == 1
    assert result.data["findings"][0]["rule_id"] == "CWE-95"
    assert (
        result.data["findings"][0]["raw"]["file_sha256"]
        == hashlib.sha256((tmp_path / "app.py").read_bytes()).hexdigest()
    )
    assert result.evidence[0].metadata["path"] == "app.py"
    assert result.evidence[0].metadata["line"] == 2
    assert result.evidence[0].sha256 is not None


def test_external_adapter_constructor_fails_closed() -> None:
    unknown = ToolManifest(
        name="unknown",
        version="1",
        description="unknown",
        scenarios=[Scenario.CODE_AUDIT],
        input_schema={},
        output_schema={},
        risk_level=RiskLevel.R1,
    )
    with pytest.raises(ValueError, match="approved external"):
        SandboxJsonTool(unknown, "http://runner", "token")

    unavailable = external_audit_manifests()[0]
    with pytest.raises(ValueError, match="immutable image"):
        SandboxJsonTool(unavailable, "http://runner", "token")

    healthy = unavailable.model_copy(deep=True)
    healthy.health_status = ToolHealth.HEALTHY
    healthy.execution.image_digest = IMAGE
    healthy.rule_bundle_digest = SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST
    with pytest.raises(ValueError, match="credentials"):
        SandboxJsonTool(healthy, "http://runner")


@pytest.mark.asyncio
async def test_external_runner_rejection_transport_failure_and_invalid_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)
    manifest = next(item for item in external_audit_manifests(default_allowlist()) if item.name == "semgrep_sast")
    (tmp_path / "app.py").write_text("print(1)", encoding="utf-8")
    context = ToolContext(
        run_id="run", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)], invocation_id="inv"
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(403))) as client:
        rejected = await SandboxJsonTool(manifest, "http://runner", "token", client).invoke({"target": "."}, context)
    assert rejected.error_code == "SANDBOX_RUNNER_REJECTED"

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        failed = await SandboxJsonTool(manifest, "http://runner", "token", client).invoke({"target": "."}, context)
    assert failed.error_code == "SANDBOX_RUNNER_UNAVAILABLE"

    denied = await SandboxJsonTool(manifest, "http://runner", "token", httpx.AsyncClient()).invoke(
        {"target": "missing"}, context
    )
    assert denied.status == ToolStatus.DENIED
    assert denied.error_code == "SANDBOX_INPUT_INVALID"


@pytest.mark.asyncio
async def test_external_adapter_rejects_response_for_another_invocation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)
    manifest = next(item for item in external_audit_manifests(default_allowlist()) if item.name == "semgrep_sast")
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "invocation_id": "another-invocation",
                "status": "success",
                "data": {"findings": []},
                "logs": {"tail": "", "sha256": "a" * 64},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await SandboxJsonTool(manifest, "http://runner", "token", client).invoke(
            {"target": "."},
            ToolContext(
                run_id="run",
                step_id="step",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="expected-invocation",
            ),
        )

    assert result.status == ToolStatus.ERROR
    assert result.error_code == "SANDBOX_INVOCATION_MISMATCH"


@pytest.mark.asyncio
async def test_external_adapter_maps_status_artifacts_and_sanitizes_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)
    manifest = next(item for item in external_audit_manifests(default_allowlist()) if item.name == "semgrep_sast")
    (tmp_path / "app.py").write_text("exec(x)", encoding="utf-8")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "invocation_id": "inv-status",
                "status": "timeout",
                "data": {
                    "findings": [
                        {
                            "rule_id": "RULE\x00",
                            "severity": "invalid",
                            "confidence": "invalid",
                            "path": "app.py",
                            "line": -2,
                            "title": None,
                            "description": None,
                            "remediation": "fix",
                        }
                    ],
                    "rules_run": 3,
                },
                "artifacts": [
                    {
                        "artifact_id": "a" * 64,
                        "relative_path": "result.json",
                        "sha256": "a" * 64,
                        "size_bytes": 2,
                        "media_type": "application/json",
                    }
                ],
                "logs": {"tail": "", "sha256": "b" * 64},
                "error_code": "bad error code",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await SandboxJsonTool(manifest, "http://runner", "token", client).invoke(
            {"target": "."},
            ToolContext(
                run_id="run",
                step_id="step",
                workspace=str(tmp_path),
                allowed_paths=[str(tmp_path)],
                invocation_id="inv-status",
            ),
        )
    assert result.status == ToolStatus.TIMEOUT
    assert result.artifacts[0].artifact_id == "a" * 64
    assert result.data["findings"] == []
    assert result.data["rejected_unbound_findings"] == 1
    assert result.error_code == "EXTERNAL_TOOL_FAILED"


def test_external_normalizer_rejects_malformed_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_external_images(monkeypatch)
    _enable_semgrep(monkeypatch)
    manifest = next(item for item in external_audit_manifests(default_allowlist()) if item.name == "semgrep_sast")
    tool = SandboxJsonTool(manifest, "http://runner", "token")
    with pytest.raises(ToolValidationError, match="array"):
        tool._normalize_findings({}, input_bindings={})
    findings, evidence, rejected = tool._normalize_findings(["bad"], input_bindings={})
    assert findings == []
    assert evidence == []
    assert len(rejected) == 1
    assert rejected[0]["reason_code"] == "RECORD_NOT_OBJECT"
    assert rejected[0]["rejected_id"].startswith("rejected-0-")
    assert tool._safe_error_code(None) is None


@pytest.mark.parametrize("tool_name", EXTERNAL_TOOL_NAMES)
def test_every_external_scanner_binds_path_line_and_hash_to_sandbox_input(tool_name: str) -> None:
    manifest = next(item for item in external_audit_manifests() if item.name == tool_name).model_copy(deep=True)
    manifest.health_status = ToolHealth.HEALTHY
    manifest.execution.image_digest = IMAGE
    if tool_name == "semgrep_sast":
        manifest.rule_bundle_digest = SEMGREP_REVIEWED_RULE_BUNDLE_DIGEST
    tool = SandboxJsonTool(manifest, "http://runner", "token")
    content = b"first\nsecond\n"
    input_file = SandboxInputFile(path="src/app.py", content_base64=base64.b64encode(content).decode())
    digest = hashlib.sha256(content).hexdigest()
    base = {
        "rule_id": "scanner.rule",
        "normalized_rule_id": "CWE-78",
        "weakness_ids": ["CWE-78"],
        "severity": "HIGH",
        "confidence": "HIGH",
        "path": "/input/src/app.py",
        "line": 2,
        "title": "Bound finding",
        "description": "Bound to an immutable sandbox input.",
    }

    findings, evidence, rejected = tool._normalize_findings(
        [
            {**base, "path": "../src/app.py"},
            {**base, "line": 3},
            base,
            {**base, "file_sha256": "0" * 64},
            {**base, "file_sha256": digest},
        ],
        input_bindings=tool._input_bindings([input_file]),
    )

    assert len(rejected) == 4
    assert {item["reason_code"] for item in rejected} == {
        "PATH_NOT_MANIFEST_BOUND",
        "LINE_OUT_OF_BOUNDS",
        "FILE_DIGEST_MISMATCH",
    }
    assert len({item["rejected_id"] for item in rejected}) == 4
    assert len(findings) == len(evidence) == 1
    assert findings[0]["path"] == "src/app.py"
    assert findings[0]["line"] == 2
    assert findings[0]["raw"]["file_sha256"] == digest
    assert evidence[0].metadata["file_sha256"] == digest
    assert evidence[0].metadata["weakness_ids"] == ["CWE-78"]


@pytest.mark.asyncio
async def test_unavailable_tool_is_typed_error() -> None:
    tool = UnavailableTool(external_audit_manifests()[0])
    result = await tool.invoke({}, ToolContext(run_id="run", step_id="step", workspace=".", allowed_paths=["."]))
    assert result.error_code == "TOOL_UNAVAILABLE"
