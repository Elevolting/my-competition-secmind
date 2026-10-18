from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secmind.cape_reverse import (
    CapeClient,
    CapeConfig,
    cape_public_key_b64,
    issue_cape_approval,
    normalize_cape_report,
)

APPROVAL_PRIVATE_KEY = Ed25519PrivateKey.generate()
APPROVAL_PUBLIC_KEY = cape_public_key_b64(APPROVAL_PRIVATE_KEY)


def _approval(sample_sha256: str, *, audience: str = "cape.example.test"):
    return issue_cape_approval(
        approval_id="approval-test",
        sample_sha256=sample_sha256,
        audience=audience,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        nonce="nonce-test",
        private_key=APPROVAL_PRIVATE_KEY,
    )


def test_cape_report_normalizes_calls_files_and_hash() -> None:
    report = {
        "target": {"file": {"sha256": "a" * 64}},
        "behavior": {
            "processes": [{"process_name": "safe.exe", "calls": [{"api": "strcmp", "arguments": {"a": "x"}}]}],
            "summary": {"files": ["C:\\Users\\analyst\\reverse_demo_result.txt"]},
        },
        "network": {"hosts": [], "http": []},
        "info": {"id": 42},
    }

    observation = normalize_cape_report(report, report_sha256=hashlib.sha256(json.dumps(report).encode()).hexdigest())

    assert observation.source == "cape"
    assert observation.events[0]["api_name"] == "strcmp"
    assert observation.artifacts["created_files"] == ["reverse_demo_result.txt"]
    assert observation.coverage["report_sha256"]


@pytest.mark.asyncio
async def test_cape_submit_poll_and_report_contract_is_hash_bound(tmp_path: Path) -> None:
    sample = tmp_path / "safe.exe"
    sample.write_bytes(b"safe")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.url.path == "/apiv2/tasks/create/file/":
            return httpx.Response(200, json={"data": {"task_ids": [7]}})
        if request.url.path == "/apiv2/tasks/status/7/":
            return httpx.Response(200, json={"data": "reported"})
        return httpx.Response(
            200,
            json={"target": {"file": {"sha256": hashlib.sha256(b"safe").hexdigest()}}, "behavior": {}, "network": {}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = CapeClient(
            CapeConfig(
                base_url="https://cape.example.test",
                token="test-token",  # noqa: S106 - synthetic credential
                allowed_hosts=("cape.example.test",),
                submit_enabled=True,
                approval_public_key=APPROVAL_PUBLIC_KEY,
            ),
            http=http,
        )
        approval = _approval(hashlib.sha256(b"safe").hexdigest())
        task_id = await client.submit(sample, approval=approval)
        with pytest.raises(PermissionError, match="R2"):
            await client.submit(sample, approval=approval)
        assert await client.status(task_id) == "reported"
        observation = await client.report(task_id, expected_sample_sha256=hashlib.sha256(b"safe").hexdigest())

    assert task_id == 7
    assert observation.sample_sha256 == hashlib.sha256(b"safe").hexdigest()
    assert [request.url.path for request in requests] == [
        "/apiv2/tasks/create/file/",
        "/apiv2/tasks/status/7/",
        "/apiv2/tasks/get/report/7/",
    ]


@pytest.mark.asyncio
async def test_cape_real_submit_is_default_off_and_credentials_are_redacted(tmp_path: Path) -> None:
    sample = tmp_path / "safe.exe"
    sample.write_bytes(b"safe")
    config = CapeConfig(
        base_url="https://cape.example.test",
        token="super-secret",  # noqa: S106 - redaction sentinel
        allowed_hosts=("cape.example.test",),
    )
    client = CapeClient(config)

    with pytest.raises(PermissionError, match="disabled"):
        await client.submit(
            sample,
            approval=_approval(hashlib.sha256(b"safe").hexdigest()),
        )
    assert "super-secret" not in repr(config)
    assert "super-secret" not in repr(client)


def test_cape_rejects_http_unlisted_host_and_wrong_approval() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CapeConfig(
            base_url="http://cape.example.test",
            token="x",  # noqa: S106 - synthetic credential
            allowed_hosts=("cape.example.test",),
        )
    with pytest.raises(ValueError, match="allowlist"):
        CapeConfig(
            base_url="https://other.example.test",
            token="x",  # noqa: S106 - synthetic credential
            allowed_hosts=("cape.example.test",),
        )


@pytest.mark.asyncio
async def test_cape_rejects_wrong_approval_auth_failure_and_report_hash_mismatch(tmp_path: Path) -> None:
    sample = tmp_path / "safe.exe"
    sample.write_bytes(b"safe")
    config = CapeConfig(
        base_url="https://cape.example.test",
        token="redaction-sentinel",  # noqa: S106 - synthetic credential
        allowed_hosts=("cape.example.test",),
        submit_enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY,
    )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(401, text="redaction-sentinel"))
    ) as http:
        client = CapeClient(config, http=http)
        invalid_approval = _approval("b" * 64)
        with pytest.raises(PermissionError, match="R2"):
            await client.submit(sample, approval=invalid_approval)
        with pytest.raises(RuntimeError, match="status 401") as failure:
            await client.status(7)
        assert "redaction-sentinel" not in str(failure.value)

    wrong_report = {
        "target": {"file": {"sha256": "b" * 64}},
        "behavior": {},
        "network": {},
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=wrong_report))
    ) as http:
        client = CapeClient(config, http=http)
        with pytest.raises(ValueError, match="sample hash"):
            await client.report(7, expected_sample_sha256="a" * 64)
