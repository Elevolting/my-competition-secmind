from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from secmind.sandbox import (
    DockerSandboxBackend,
    MockSandboxBackend,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxRunner,
    SandboxToolSpec,
    token_matches,
)
from secmind.sandbox_api import create_sandbox_app

IMAGE = "secmind-bandit@sha256:" + ("a" * 64)


def spec(**limits: int) -> SandboxToolSpec:
    return SandboxToolSpec(
        name="bandit_python_audit",
        image_digest=IMAGE,
        entrypoint=("python", "/opt/secmind-bandit/run.py"),
        limits=SandboxLimits(**limits),
    )


def invocation(tool_name: str = "bandit_python_audit") -> SandboxInvocation:
    return SandboxInvocation(
        invocation_id="run-1.step-1.attempt-1",
        tool_name=tool_name,
        files=[
            SandboxInputFile(
                path="src/app.py",
                content_base64=base64.b64encode(b"print('safe')\n").decode(),
            )
        ],
    )


def test_invocation_rejects_paths_commands_and_images() -> None:
    with pytest.raises(ValidationError):
        SandboxInputFile(path="../secret", content_base64="")
    with pytest.raises(ValidationError):
        SandboxInputFile(path="/etc/passwd", content_base64="")
    with pytest.raises(ValidationError):
        SandboxInvocation(
            invocation_id="run-1",
            tool_name="bandit_python_audit",
            files=[],
            image="attacker/image:latest",  # type: ignore[call-arg]
            command=["sh"],  # type: ignore[call-arg]
        )


def test_tool_spec_requires_digest_and_fixed_entrypoint() -> None:
    with pytest.raises(ValueError, match="pinned"):
        SandboxToolSpec(name="bandit_python_audit", image_digest="bandit:latest", entrypoint=("run",))
    with pytest.raises(ValueError, match="entrypoint"):
        SandboxToolSpec(name="bandit_python_audit", image_digest=IMAGE, entrypoint=())


async def test_runner_uses_allowlist_and_mock_backend() -> None:
    backend = MockSandboxBackend({"findings": [{"test_id": "B105"}]})
    runner = SandboxRunner(backend, {"bandit_python_audit": spec()})

    result = await runner.execute(invocation())

    assert result.status == "success"
    assert result.data["findings"][0]["test_id"] == "B105"
    assert backend.calls[0][0].image_digest == IMAGE
    assert backend.calls[0][1].files[0].path == "src/app.py"
    assert result.logs.sha256 == hashlib.sha256(b"mock sandbox execution").hexdigest()


async def test_runner_denies_unknown_tool_and_oversized_input() -> None:
    backend = MockSandboxBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": spec(max_input_bytes=3)})
    with pytest.raises(SandboxError, match="not registered") as unknown:
        await runner.execute(invocation("untrusted_tool"))
    assert unknown.value.code == "TOOL_NOT_ALLOWLISTED"

    with pytest.raises(SandboxError, match="exceeds") as oversized:
        await runner.execute(invocation())
    assert oversized.value.code == "INPUT_TOO_LARGE"
    assert backend.calls == []


def test_runner_api_requires_constant_time_bearer_token() -> None:
    backend = MockSandboxBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": spec()})
    app = create_sandbox_app(runner, "test-only-runner-token")
    payload = invocation().model_dump(mode="json")

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.post("/internal/v1/invocations", json=payload).status_code == 401
        assert (
            client.post(
                "/internal/v1/invocations",
                json=payload,
                headers={"Authorization": "Bearer wrong"},
            ).status_code
            == 401
        )
        response = client.post(
            "/internal/v1/invocations",
            json=payload,
            headers={"Authorization": "Bearer test-only-runner-token"},
        )

    assert response.status_code == 200
    assert response.json()["invocation_id"] == payload["invocation_id"]
    assert backend.cleanup_calls == 1
    assert token_matches("same", "same")
    assert not token_matches("same", "different")


def test_runner_api_fails_closed_without_token() -> None:
    app = create_sandbox_app(
        SandboxRunner(MockSandboxBackend(), {"bandit_python_audit": spec()}),
        "",
    )
    with TestClient(app) as client:
        response = client.post("/internal/v1/invocations", json=invocation().model_dump(mode="json"))
    assert response.status_code == 503


def _output_tar(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


class ArchiveContainer:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def get_archive(self, _: str):
        return iter([self.raw]), {}


class FakeVolume:
    def __init__(self, name: str) -> None:
        self.name = name
        self.removed = False

    def remove(self, force: bool) -> None:
        assert force
        self.removed = True


class FakeVolumes:
    def __init__(self) -> None:
        self.created: list[FakeVolume] = []

    def create(self, **_: object) -> FakeVolume:
        volume = FakeVolume(f"volume-{len(self.created)}")
        self.created.append(volume)
        return volume


class FakeContainer(ArchiveContainer):
    def __init__(self, raw: bytes, log: bytes = b"") -> None:
        super().__init__(raw)
        self.log = log
        self.started = False
        self.removed = False
        self.archive_received = False

    def put_archive(self, path: str, raw: bytes) -> None:
        assert path == "/input"
        assert raw
        self.archive_received = True

    def start(self) -> None:
        self.started = True

    def wait(self, timeout: int) -> dict[str, int]:
        assert timeout > 0
        return {"StatusCode": 0}

    def logs(self, **_: object):
        return iter([self.log])

    def remove(self, force: bool) -> None:
        assert force
        self.removed = True


class FakeContainers:
    def __init__(self, raw: bytes) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.instances = [FakeContainer(raw), FakeContainer(raw, b"full tool log")]

    def create(self, image: str, **kwargs: object) -> FakeContainer:
        self.calls.append((image, kwargs))
        return self.instances[len(self.calls) - 1]


class FakeDockerClient:
    def __init__(self, raw: bytes) -> None:
        self.volumes = FakeVolumes()
        self.containers = FakeContainers(raw)


def test_output_parser_validates_result_and_hashes_artifacts() -> None:
    result_json = json.dumps({"status": "success", "data": {"findings": []}}).encode()
    artifact = b"report contents"
    raw = _output_tar({"output/result.json": result_json, "output/report.txt": artifact})

    artifacts, result = DockerSandboxBackend._read_outputs(ArchiveContainer(raw), 1024 * 1024)

    assert result["status"] == "success"
    assert artifacts[0].relative_path == "report.txt"
    assert artifacts[0].sha256 == hashlib.sha256(artifact).hexdigest()
    assert base64.b64decode(artifacts[0].content_base64 or "") == artifact


def test_output_parser_rejects_symlink_and_invalid_json() -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        link = tarfile.TarInfo("output/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
    with pytest.raises(SandboxError) as unsafe:
        DockerSandboxBackend._read_outputs(ArchiveContainer(stream.getvalue()), 20_000)
    assert unsafe.value.code == "INVALID_ARTIFACT_PATH"

    raw = _output_tar({"output/result.json": b"not json"})
    with pytest.raises(SandboxError) as invalid:
        DockerSandboxBackend._read_outputs(ArchiveContainer(raw), 1024)
    assert invalid.value.code == "INVALID_RESULT_JSON"


async def test_docker_backend_applies_non_bypassable_security_policy() -> None:
    result_json = json.dumps({"status": "success", "data": {"findings": []}}).encode()
    client = FakeDockerClient(_output_tar({"output/result.json": result_json}))
    backend = DockerSandboxBackend(client=client)

    result = await backend.execute(spec(), invocation())

    assert result.status == "success"
    assert result.logs.sha256 == hashlib.sha256(b"full tool log").hexdigest()
    assert len(client.containers.calls) == 2
    helper_image, helper_policy = client.containers.calls[0]
    assert helper_image == "sha256:" + ("0" * 64)
    assert helper_policy["entrypoint"] == ["/opt/secmind-stage"]
    assert helper_policy["network_mode"] == "none"
    assert helper_policy["read_only"] is True
    assert helper_policy["cap_drop"] == ["ALL"]
    assert helper_policy["mem_limit"] == 64 * 1024 * 1024
    assert helper_policy["pids_limit"] == 16
    assert helper_policy["log_config"]["config"]["max-size"] == "1m"
    image, policy = client.containers.calls[1]
    assert image == IMAGE
    assert policy["entrypoint"] == ["python", "/opt/secmind-bandit/run.py"]
    assert policy["network_mode"] == "none"
    assert policy["read_only"] is True
    assert policy["user"] == "65532:65532"
    assert policy["cap_drop"] == ["ALL"]
    assert policy["security_opt"] == ["no-new-privileges:true"]
    assert policy["mem_limit"] == 512 * 1024 * 1024
    assert policy["nano_cpus"] == 1_000_000_000
    assert policy["pids_limit"] == 64
    assert policy["log_config"]["config"]["max-size"] == "1m"
    assert "command" not in policy
    assert all(volume.removed for volume in client.volumes.created)
    assert all(container.removed for container in client.containers.instances)
