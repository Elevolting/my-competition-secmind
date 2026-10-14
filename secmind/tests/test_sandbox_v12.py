from __future__ import annotations

import asyncio
import base64
import hashlib
import unicodedata
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.capability import (
    CapabilityError,
    CapabilityTicketIssuer,
    CapabilityTicketVerifier,
    SqliteCapabilityReplayStore,
)
from secmind.sandbox import (
    DockerSandboxBackend,
    MockSandboxBackend,
    SandboxArtifact,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxLog,
    SandboxResult,
    SandboxRunner,
    SandboxStagingSpec,
    SandboxToolSpec,
    invocation_input_sha256,
)
from secmind.sandbox_api import create_sandbox_app

IMAGE = "tool@sha256:" + ("a" * 64)


def _spec(*, parallelism: int = 2) -> SandboxToolSpec:
    return SandboxToolSpec(
        name="bandit_python_audit",
        image_digest=IMAGE,
        entrypoint=("python", "run.py"),
        limits=SandboxLimits(max_parallelism=parallelism),
    )


def _invocation(*, fence: int = 7) -> SandboxInvocation:
    return SandboxInvocation(
        run_id="run-1",
        invocation_id="invocation-1",
        tool_name="bandit_python_audit",
        lease_fence=fence,
        files=[SandboxInputFile(path="src/app.py", content_base64=base64.b64encode(b"print(1)\n").decode())],
    )


@pytest.mark.parametrize(
    "path",
    ["src/a\x00.py", "src/a\n.py", "src/" + "/".join(["deep"] * 33) + "/a.py"],
)
def test_input_paths_reject_controls_and_excessive_depth(path: str) -> None:
    with pytest.raises(ValidationError):
        SandboxInputFile(path=path, content_base64="")


def test_input_paths_require_nfc() -> None:
    decomposed = unicodedata.normalize("NFD", "café.py")
    assert decomposed != "café.py"
    with pytest.raises(ValidationError, match="NFC"):
        SandboxInputFile(path=decomposed, content_base64="")


def test_capability_is_bound_short_lived_and_single_use() -> None:
    issuer = CapabilityTicketIssuer.generate(ttl_seconds=60)
    now = 1_700_000_000
    verifier = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), clock=lambda: now)
    request = _invocation()
    policy = _spec().capability_policy()
    ticket = issuer.issue(
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        input_sha256=invocation_input_sha256(request),
        fence=request.lease_fence,
        policy=policy,
        now=now,
    )
    claims = verifier.verify_and_consume(
        ticket,
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        input_sha256=invocation_input_sha256(request),
        fence=request.lease_fence,
        policy=policy,
    )
    assert claims.fence == 7
    with pytest.raises(CapabilityError) as replay:
        verifier.verify_and_consume(
            ticket,
            invocation_id=request.invocation_id,
            tool_name=request.tool_name,
            input_sha256=invocation_input_sha256(request),
            fence=request.lease_fence,
            policy=policy,
        )
    assert replay.value.code == "CAPABILITY_REPLAYED"

    expired_verifier = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), clock=lambda: now + 61)
    with pytest.raises(CapabilityError) as expired:
        expired_verifier.verify_and_consume(
            ticket,
            invocation_id=request.invocation_id,
            tool_name=request.tool_name,
            input_sha256=invocation_input_sha256(request),
            fence=request.lease_fence,
            policy=policy,
        )
    assert expired.value.code == "CAPABILITY_EXPIRED"


def test_capability_replay_is_rejected_after_verifier_restart(tmp_path: Path) -> None:
    issuer = CapabilityTicketIssuer.generate()
    request = _invocation()
    policy = _spec().capability_policy()
    ticket = issuer.issue(
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        input_sha256=invocation_input_sha256(request),
        fence=request.lease_fence,
        policy=policy,
    )
    database = tmp_path / "replay.db"
    first_store = SqliteCapabilityReplayStore(database)
    first = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), replay_store=first_store)
    first.verify_and_consume(
        ticket,
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        input_sha256=invocation_input_sha256(request),
        fence=request.lease_fence,
        policy=policy,
    )
    first_store.close()
    second_store = SqliteCapabilityReplayStore(database)
    second = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), replay_store=second_store)
    with pytest.raises(CapabilityError) as replay:
        second.verify_and_consume(
            ticket,
            invocation_id=request.invocation_id,
            tool_name=request.tool_name,
            input_sha256=invocation_input_sha256(request),
            fence=request.lease_fence,
            policy=policy,
        )
    second_store.close()
    assert replay.value.code == "CAPABILITY_REPLAYED"


def test_runner_api_requires_bound_capability_and_rejects_replay() -> None:
    issuer = CapabilityTicketIssuer.generate()
    verifier = CapabilityTicketVerifier.from_pem(issuer.public_key_pem())
    request = _invocation()
    runner = SandboxRunner(MockSandboxBackend(), {request.tool_name: _spec()})
    ticket = issuer.issue(
        invocation_id=request.invocation_id,
        tool_name=request.tool_name,
        input_sha256=invocation_input_sha256(request),
        fence=request.lease_fence,
        policy=runner.capability_policy(request.tool_name),
    )
    with TestClient(create_sandbox_app(runner, capability_verifier=verifier)) as client:
        payload = request.model_dump(mode="json")
        assert client.post("/internal/v1/invocations", json=payload).status_code == 401
        first = client.post("/internal/v1/invocations", json=payload, headers={"Authorization": f"Bearer {ticket}"})
        replay = client.post("/internal/v1/invocations", json=payload, headers={"Authorization": f"Bearer {ticket}"})
    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "CAPABILITY_REPLAYED"


def test_runner_api_rejects_request_before_parse() -> None:
    runner = SandboxRunner(MockSandboxBackend(), {"bandit_python_audit": _spec()})
    with TestClient(create_sandbox_app(runner, "dev-token", max_request_bytes=100)) as client:
        response = client.post(
            "/internal/v1/invocations",
            content=b"x" * 101,
            headers={"Authorization": "Bearer dev-token", "content-type": "application/json"},
        )
    assert response.status_code == 413


def test_control_token_can_only_cancel_a_named_invocation() -> None:
    backend = MockSandboxBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": _spec()})
    with TestClient(
        create_sandbox_app(runner, "dev-token", control_token="control-token")  # noqa: S106
    ) as client:
        denied = client.delete(
            "/internal/v1/invocations/invocation-1",
            headers={"Authorization": "Bearer dev-token"},
        )
        assert denied.status_code == 401
        response = client.delete(
            "/internal/v1/invocations/invocation-1",
            headers={"Authorization": "Bearer control-token"},
        )
        assert response.status_code == 200
        assert response.json()["cancelled"] is True
        assert backend.cancelled == ["invocation-1"]


def test_control_token_lists_only_named_run_resources() -> None:
    backend = MockSandboxBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": _spec()})

    async def exercise() -> list[dict[str, object]]:
        started = asyncio.Event()
        release = asyncio.Event()

        class WaitingBackend(MockSandboxBackend):
            async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
                started.set()
                await release.wait()
                return await super().execute(spec, invocation)

        waiting_runner = SandboxRunner(WaitingBackend(), {"bandit_python_audit": _spec()})
        task = asyncio.create_task(waiting_runner.execute(_invocation()))
        await started.wait()
        resources = [item.model_dump(mode="json") for item in await waiting_runner.list_resources("run-1")]
        assert await waiting_runner.list_resources("other-run") == []
        release.set()
        await task
        assert await waiting_runner.list_resources("run-1") == []
        return resources

    resources = asyncio.run(exercise())
    assert resources == [
        {
            "schema_version": "1.1",
            "run_id": "run-1",
            "resource_id": "invocation:invocation-1",
            "invocation_id": "invocation-1",
            "fence": 7,
            "active": True,
        }
    ]
    with TestClient(
        create_sandbox_app(runner, "dev-token", control_token="control-token")  # noqa: S106 - synthetic test token
    ) as client:
        assert client.get("/internal/v1/resources", params={"run_id": "run-1"}).status_code == 401
        response = client.get(
            "/internal/v1/resources",
            params={"run_id": "run-1"},
            headers={"Authorization": "Bearer control-token"},
        )
    assert response.status_code == 200
    assert response.json()["resources"] == []


def test_content_addressed_store_persists_and_reverifies(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path)
    content = b"durable report"
    digest = hashlib.sha256(content).hexdigest()
    stored = store.put(content, expected_sha256=digest, media_type="text/plain")
    assert stored.artifact_id == digest
    assert stored.storage_ref == f"sha256/{digest[:2]}/{digest}"
    assert store.read(digest) == content
    store.path_for(digest).write_bytes(b"tampered")
    with pytest.raises(ArtifactStoreError):
        store.read(digest)


class ArtifactBackend(MockSandboxBackend):
    async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        content = b"report"
        return SandboxResult(
            invocation_id=invocation.invocation_id,
            status="success",
            artifacts=[
                SandboxArtifact(
                    artifact_id="temporary",
                    relative_path="report.txt",
                    sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                    content_base64=base64.b64encode(content).decode(),
                )
            ],
            logs=SandboxLog(sha256=hashlib.sha256(b"").hexdigest()),
            cleanup_confirmed=True,
        )


async def test_runner_persists_artifacts_before_return(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path)
    runner = SandboxRunner(ArtifactBackend(), {"bandit_python_audit": _spec()}, artifact_store=store)
    result = await runner.execute(_invocation())
    artifact = result.artifacts[0]
    assert len(artifact.artifact_id) == 64
    assert artifact.content_base64 is None
    assert store.read(artifact.artifact_id) == b"report"


class BlockingBackend(MockSandboxBackend):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
        self.started.set()
        await self.release.wait()
        return await super().execute(spec, invocation)


async def test_runner_enforces_global_concurrency_limit() -> None:
    backend = BlockingBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": _spec()}, max_parallelism=1)
    first = asyncio.create_task(runner.execute(_invocation()))
    await backend.started.wait()
    with pytest.raises(SandboxError, match="concurrency limit"):
        await runner.execute(_invocation())
    backend.release.set()
    await first


class DaemonInfoClient:
    def __init__(self, options: list[str]) -> None:
        self.options = options

    def info(self) -> dict[str, list[str]]:
        return {"SecurityOptions": self.options}


def test_production_backend_requires_rootless_daemon() -> None:
    with pytest.raises(SandboxError, match="not rootless"):
        DockerSandboxBackend(client=DaemonInfoClient(["name=seccomp"]), require_rootless=True)
    DockerSandboxBackend(client=DaemonInfoClient(["name=rootless"]), require_rootless=True)


async def test_docker_readiness_verifies_daemon_mode_and_all_images() -> None:
    requested: list[str] = []

    class Images:
        def get(self, image: str) -> object:
            requested.append(image)
            return object()

    class ReadyDocker:
        images = Images()

        def ping(self) -> bool:
            return True

        def info(self) -> dict[str, list[str]]:
            return {"SecurityOptions": ["name=rootless"]}

    staging = "staging@sha256:" + ("b" * 64)
    backend = DockerSandboxBackend(
        client=ReadyDocker(),
        require_rootless=True,
        staging_spec=SandboxStagingSpec(image_digest=staging),
    )
    status = await backend.readiness((_spec(),))
    assert status == {"backend": "docker", "daemon": "ok", "images": 2, "rootless": True}
    assert set(requested) == {IMAGE, staging}


def test_runner_readiness_is_fail_closed_when_execution_plane_is_unavailable() -> None:
    class UnavailableBackend(MockSandboxBackend):
        async def readiness(self, _specs: tuple[SandboxToolSpec, ...]) -> dict[str, object]:
            raise SandboxError("RUNNER_NOT_READY", "unavailable")

    runner = SandboxRunner(UnavailableBackend(), {"bandit_python_audit": _spec()})
    with TestClient(create_sandbox_app(runner, "dev-token")) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/health/ready")
        compatibility = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "RUNNER_NOT_READY"
    assert compatibility.status_code == 503
