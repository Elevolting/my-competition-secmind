from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from secmind.sandbox import SandboxInputFile
from secmind.sandbox_client import SandboxBanditTool
from secmind.schemas import ToolContext, ToolStatus


async def test_sandbox_bandit_adapter_normalizes_findings(tmp_path: Path) -> None:
    source = b"print('ok')"
    (tmp_path / "app.py").write_bytes(source)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-token"
        payload = json.loads(request.content)
        assert payload["files"][0]["path"] == "app.py"
        assert base64.b64decode(payload["files"][0]["content_base64"]) == source
        # The result must remain bound to the bytes in this request even if the
        # workspace changes before the runner response is normalized.
        (tmp_path / "app.py").write_bytes(b"changed\nafter\nrequest\n")
        return httpx.Response(
            200,
            json={
                "schema_version": "1.1",
                "invocation_id": "invocation-1",
                "status": "success",
                "data": {
                    "findings": [
                        {
                            "test_id": "B602",
                            "test_name": "subprocess_popen_with_shell_equals_true",
                            "issue_severity": "HIGH",
                            "issue_confidence": "HIGH",
                            "filename": "/input/app.py",
                            "line_number": 1,
                            "issue_text": "shell=True",
                        },
                        {
                            "test_id": "B602",
                            "filename": "/input/../app.py",
                            "line_number": 1,
                        },
                        {
                            "test_id": "B602",
                            "filename": "/input/unknown.py",
                            "line_number": 1,
                        },
                        {
                            "test_id": "B602",
                            "filename": "/input/app.py",
                            "line_number": 2,
                        },
                    ]
                },
                "summary": "one finding",
                "artifacts": [
                    {
                        "artifact_id": "report",
                        "relative_path": "report.json",
                        "sha256": hashlib.sha256(b"report").hexdigest(),
                        "size_bytes": 6,
                        "media_type": "application/json",
                    }
                ],
                "logs": {"sha256": hashlib.sha256(b"").hexdigest()},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tool = SandboxBanditTool("http://sandbox", "test-token", client)
    result = await tool.invoke(
        {"target": "."},
        ToolContext(
            run_id="run",
            step_id="step",
            workspace=str(tmp_path),
            allowed_paths=[str(tmp_path)],
            invocation_id="invocation-1",
            idempotency_key="run:step:1",
        ),
    )
    await client.aclose()
    assert result.status == ToolStatus.SUCCESS
    assert result.error_code is None
    assert len(result.data["findings"]) == 1
    assert result.data["rejected_unbound_findings"] == 3
    assert result.data["coverage"] == {
        "status": "partial",
        "accepted_findings": 1,
        "rejected_unbound_findings": 3,
        "complete": False,
    }
    assert result.data["input_manifest"] == [
        {
            "path": "app.py",
            "sha256": hashlib.sha256(source).hexdigest(),
            "size_bytes": len(source),
        }
    ]
    assert len(result.data["input_manifest_digest"]) == 64
    assert len(result.data["rule_bundle_digest"]) == 64
    assert result.evidence[0].metadata["input_manifest_digest"] == result.data["input_manifest_digest"]
    assert len(result.evidence) == 1
    assert len(result.artifacts) == 1
    assert "quarantined 3 unbound" in result.summary


def test_sandbox_bandit_rejects_unbound_paths_and_lines() -> None:
    source = b"first\nsecond\n"
    input_file = SandboxInputFile(
        path="src/app.py",
        content_base64=base64.b64encode(source).decode(),
    )
    tool = SandboxBanditTool("http://sandbox", "test-token")
    binding = tool._input_bindings([input_file])
    base = {
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "filename": "/input/src/app.py",
        "line_number": 2,
        "issue_text": "shell=True",
        "file_sha256": "0" * 64,
    }

    findings, rejected = tool._bind_runner_findings(
        [
            base,
            {**base, "filename": "/input/../src/app.py"},
            {**base, "filename": "/workspace/src/app.py"},
            {**base, "filename": "src/missing.py"},
            {**base, "filename": "src\\app.py"},
            {**base, "line_number": 0},
            {**base, "line_number": 3},
            {**base, "line_number": True},
        ],
        input_bindings=binding,
    )

    assert findings == [
        {
            **base,
            "filename": "src/app.py",
            "file_sha256": hashlib.sha256(source).hexdigest(),
        }
    ]
    assert rejected == 7


@pytest.mark.asyncio
async def test_sandbox_bandit_rejects_response_for_another_invocation(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "invocation_id": "another-invocation",
                "status": "success",
                "data": {"findings": []},
                "logs": {"tail": "", "sha256": hashlib.sha256(b"").hexdigest()},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await SandboxBanditTool("http://sandbox", "test-token", client).invoke(
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
