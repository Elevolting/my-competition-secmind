from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.capability import CapabilityError, CapabilityTicketIssuer, CapabilityTicketVerifier
from secmind.sandbox import (
    CREATED_LABEL,
    DockerSandboxBackend,
    SandboxArtifact,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxLog,
    SandboxResult,
    SandboxRunner,
    SandboxToolSpec,
    default_allowlist,
)
from secmind.sandbox_api import create_production_app, create_sandbox_app
from secmind.sandbox_client import SandboxBanditTool
from secmind.schemas import Evidence, PlanStep, StepRuntime, StepStatus, ToolContext, ToolStatus
from secmind.tool_assurance import deterministic_negative_coverage_complete

IMAGE = "tool@sha256:" + ("a" * 64)


def _spec(**limits: Any) -> SandboxToolSpec:
    return SandboxToolSpec(
        name="bandit_python_audit",
        image_digest=IMAGE,
        entrypoint=("run",),
        limits=SandboxLimits(**limits),
    )


def _invocation() -> SandboxInvocation:
    return SandboxInvocation(
        invocation_id="run.step.attempt",
        tool_name="bandit_python_audit",
        files=[SandboxInputFile(path="app.py", content_base64=base64.b64encode(b"print(1)").decode())],
    )


def _tar(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, content in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
    return stream.getvalue()


class _Volume:
    def __init__(self, name: str, *, labels: dict[str, str] | None = None, fail: bool = False) -> None:
        self.name = name
        self.attrs = {"Labels": labels or {}}
        self.fail = fail
        self.removed = False

    def remove(self, force: bool = False) -> None:
        if self.fail:
            raise RuntimeError("remove failed")
        self.removed = force


class _Container:
    def __init__(
        self,
        archive: bytes,
        *,
        exit_code: int = 0,
        timeout_once: bool = False,
        helper_code: int = 0,
        labels: dict[str, str] | None = None,
        running: bool = False,
        fail_remove: bool = False,
    ) -> None:
        self.archive = archive
        self.exit_code = exit_code
        self.timeout_once = timeout_once
        self.helper_code = helper_code
        self.labels = labels or {}
        self.attrs = {"Config": {"Labels": self.labels}, "State": {"Running": running}}
        self.fail_remove = fail_remove
        self.waits = 0
        self.killed = False
        self.removed = False

    def put_archive(self, _path: str, _raw: bytes) -> None:
        return None

    def start(self) -> None:
        return None

    def wait(self, timeout: int) -> dict[str, int]:
        self.waits += 1
        if self.timeout_once and self.waits == 1:
            raise TimeoutError("deadline")
        if timeout == 30:
            return {"StatusCode": self.helper_code}
        return {"StatusCode": self.exit_code}

    def kill(self) -> None:
        self.killed = True

    def logs(self, **_kwargs: Any):
        return iter([b"012345", b"6789"])

    def get_archive(self, _path: str):
        return iter([self.archive]), {}

    def remove(self, force: bool = False) -> None:
        if self.fail_remove:
            raise RuntimeError("remove failed")
        self.removed = force


class _Collection:
    def __init__(self, created: list[Any] | None = None, listed: list[Any] | None = None) -> None:
        self.created = created or []
        self.listed = listed or []
        self.index = 0

    def create(self, *_args: Any, **_kwargs: Any):
        value = self.created[self.index]
        self.index += 1
        return value

    def list(self, **_kwargs: Any):
        return self.listed


class _Volumes(_Collection):
    def create(self, **_kwargs: Any):
        value = _Volume(f"volume-{self.index}")
        self.created.append(value)
        self.index += 1
        return value


class _Docker:
    def __init__(self, helper: _Container, tool: _Container) -> None:
        self.containers = _Collection([helper, tool])
        self.volumes = _Volumes()


@pytest.mark.parametrize(
    ("exit_code", "timed_out", "status", "error"),
    [(9, False, "error", "TOOL_EXIT_NONZERO"), (137, True, "timeout", "SANDBOX_TIMEOUT")],
)
async def test_docker_backend_nonzero_and_timeout(exit_code: int, timed_out: bool, status: str, error: str) -> None:
    raw = _tar({"output/result.json": b'{"status":"success"}'})
    helper = _Container(raw)
    tool = _Container(raw, exit_code=exit_code, timeout_once=timed_out)
    backend = DockerSandboxBackend(client=_Docker(helper, tool))
    result = await backend.execute(_spec(max_log_tail_bytes=4), _invocation())
    assert result.status == status
    assert result.error_code == error
    assert result.logs.tail == "6789"
    assert result.logs.truncated
    assert tool.killed is timed_out


async def test_docker_backend_staging_and_untyped_failures_cleanup() -> None:
    raw = _tar({"output/result.json": b"{}"})
    helper = _Container(raw, helper_code=2, fail_remove=True)
    docker = _Docker(helper, _Container(raw))
    with pytest.raises(SandboxError) as exc:
        await DockerSandboxBackend(client=docker).execute(_spec(), _invocation())
    assert exc.value.code == "STAGING_FAILED"
    assert all(volume.removed for volume in docker.volumes.created)

    class BrokenVolumes:
        calls = 0

        def create(self, **_kwargs: Any):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("disk full")
            return _Volume("input")

    broken = SimpleNamespace(volumes=BrokenVolumes(), containers=_Collection())
    with pytest.raises(SandboxError) as wrapped:
        await DockerSandboxBackend(client=broken).execute(_spec(), _invocation())
    assert wrapped.value.code == "SANDBOX_EXECUTION_FAILED"


async def test_docker_cancel_and_orphan_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    old = str(1)
    recent = str(10_000)
    candidates = [
        _Container(b"", labels={CREATED_LABEL: old}, running=True),
        _Container(b"", labels={CREATED_LABEL: recent}, running=True),
        _Container(b"", labels={CREATED_LABEL: recent}, running=False, fail_remove=True),
    ]
    volumes = [_Volume("old", labels={CREATED_LABEL: old}), _Volume("new", labels={CREATED_LABEL: recent})]
    cancel_collection = _Collection(listed=[candidates[0]])
    client = SimpleNamespace(containers=cancel_collection, volumes=_Collection(listed=volumes))
    backend = DockerSandboxBackend(client=client, orphan_ttl_seconds=100)
    monkeypatch.setattr("secmind.sandbox.time.time", lambda: 10_000)
    assert await backend.cancel("id")
    client.containers.listed = candidates
    assert await backend.cleanup_orphans() == 2
    assert candidates[0].removed
    assert volumes[0].removed
    assert DockerSandboxBackend._label_epoch({CREATED_LABEL: object()}) == 0


def test_output_parser_rejects_limits_duplicates_and_missing_result() -> None:
    duplicate = io.BytesIO()
    with tarfile.open(fileobj=duplicate, mode="w") as archive:
        for _ in range(2):
            item = tarfile.TarInfo("output/a.txt")
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
    container = SimpleNamespace(get_archive=lambda _path: (iter([duplicate.getvalue()]), {}))
    with pytest.raises(SandboxError) as duplicate_error:
        DockerSandboxBackend._read_outputs(container, 10000)
    assert duplicate_error.value.code == "DUPLICATE_ARTIFACT_PATH"

    for raw, limit, code in [
        (_tar({"output/a": b"x"}), 10_000, "RESULT_MISSING"),
        (_tar({"output/result.json": b"[]"}), 10_000, "INVALID_RESULT_JSON"),
        (_tar({"output/result.json": b"{}", "output/a": b"too much"}), 4, "OUTPUT_TOO_LARGE"),
    ]:
        container = SimpleNamespace(get_archive=lambda _path, raw=raw: (iter([raw]), {}))
        with pytest.raises(SandboxError) as exc:
            DockerSandboxBackend._read_outputs(container, limit)
        assert exc.value.code == code


def test_docker_volumes_are_bounded_tmpfs_and_invalid_sizes_fail_closed() -> None:
    options = DockerSandboxBackend._bounded_volume_options(size_bytes=1024)
    assert options["driver"] == "local"
    assert options["driver_opts"]["type"] == "tmpfs"
    assert "size=1024" in options["driver_opts"]["o"]
    with pytest.raises(SandboxError, match="volume size"):
        DockerSandboxBackend._bounded_volume_options(size_bytes=0)


async def test_runner_artifact_and_tool_slot_failures(tmp_path: Path) -> None:
    class MissingContent:
        async def execute(self, _spec: Any, invocation: SandboxInvocation) -> SandboxResult:
            return SandboxResult(
                invocation_id=invocation.invocation_id,
                status="success",
                artifacts=[SandboxArtifact(artifact_id="temp", relative_path="a", sha256="0" * 64, size_bytes=1)],
                logs=SandboxLog(sha256="0" * 64),
                cleanup_confirmed=True,
            )

        async def cancel(self, _invocation_id: str) -> bool:
            return False

        async def cleanup_orphans(self) -> int:
            return 0

    runner = SandboxRunner(
        MissingContent(), {"bandit_python_audit": _spec()}, artifact_store=ContentAddressedArtifactStore(tmp_path)
    )
    with pytest.raises(SandboxError) as missing:
        await runner.execute(_invocation())
    assert missing.value.code == "ARTIFACT_CONTENT_MISSING"
    with pytest.raises(SandboxError):
        runner.capability_policy("missing")
    with pytest.raises(ValueError):
        SandboxRunner(MissingContent(), {}, max_parallelism=0)


def test_artifact_store_rejects_size_digest_ids_and_corruption(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path, max_artifact_bytes=3)
    with pytest.raises(ArtifactStoreError, match="size limit"):
        store.put(b"long")
    with pytest.raises(ArtifactStoreError, match="digest"):
        store.put(b"abc", expected_sha256="0" * 64)
    stored = store.put(b"abc")
    assert store.put(b"abc").artifact_id == stored.artifact_id
    with pytest.raises(ArtifactStoreError, match="invalid artifact id"):
        store.path_for("../bad")
    store.path_for(stored.artifact_id).write_bytes(b"xx")
    with pytest.raises(ArtifactStoreError, match="size"):
        store.put(b"abc")
    with pytest.raises(FileNotFoundError):
        ContentAddressedArtifactStore(tmp_path / "other").path_for("f" * 64)


def test_capability_rejects_all_malformed_and_binding_cases() -> None:
    with pytest.raises(ValueError):
        CapabilityTicketIssuer.generate(ttl_seconds=0)
    issuer = CapabilityTicketIssuer.generate()
    with pytest.raises(ValueError, match="binding"):
        issuer.issue(invocation_id="i", tool_name="t", input_sha256="bad", fence=0, policy={})
    now = 1000
    ticket = issuer.issue(invocation_id="i", tool_name="t", input_sha256="a" * 64, fence=3, policy={"x": 1}, now=now)
    verifier = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), clock=lambda: now)
    for malformed, code in [("bad", "CAPABILITY_MALFORMED"), ("!!.!!", "CAPABILITY_INVALID")]:
        with pytest.raises(CapabilityError) as exc:
            verifier.verify_and_consume(
                malformed, invocation_id="i", tool_name="t", input_sha256="a" * 64, fence=3, policy={"x": 1}
            )
        assert exc.value.code == code
    tampered = ticket[:-1] + ("A" if ticket[-1] != "A" else "B")
    with pytest.raises(CapabilityError) as invalid:
        verifier.verify_and_consume(
            tampered, invocation_id="i", tool_name="t", input_sha256="a" * 64, fence=3, policy={"x": 1}
        )
    assert invalid.value.code == "CAPABILITY_INVALID"
    with pytest.raises(CapabilityError) as binding:
        verifier.verify_and_consume(
            ticket, invocation_id="other", tool_name="t", input_sha256="a" * 64, fence=3, policy={"x": 1}
        )
    assert binding.value.code == "CAPABILITY_BINDING_MISMATCH"


def test_capability_not_yet_valid_and_key_types() -> None:
    issuer = CapabilityTicketIssuer.generate()
    ticket = issuer.issue(invocation_id="i", tool_name="t", input_sha256="a" * 64, fence=0, policy={}, now=100)
    verifier = CapabilityTicketVerifier.from_pem(issuer.public_key_pem(), clock=lambda: 0)
    with pytest.raises(CapabilityError) as exc:
        verifier.verify_and_consume(ticket, invocation_id="i", tool_name="t", input_sha256="a" * 64, fence=0, policy={})
    assert exc.value.code == "CAPABILITY_NOT_YET_VALID"


def _context(workspace: Path) -> ToolContext:
    return ToolContext(
        run_id="run", step_id="step", workspace=str(workspace), allowed_paths=[str(workspace)], invocation_id="inv"
    )


async def test_sandbox_client_success_rejection_transport_error_and_credentials(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("password = 'x'", encoding="utf-8")
    artifact = b"report"
    response_body = SandboxResult(
        invocation_id="inv",
        status="success",
        data={"findings": []},
        summary="ok",
        artifacts=[
            SandboxArtifact(
                artifact_id="a" * 64,
                relative_path="sha256/aa/" + ("a" * 64),
                sha256=hashlib.sha256(artifact).hexdigest(),
                size_bytes=len(artifact),
            )
        ],
        logs=SandboxLog(sha256="0" * 64),
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer ticket"
        return httpx.Response(200, json=response_body.model_dump(mode="json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tool = SandboxBanditTool("http://runner/", client=client, capability_ticket_provider=lambda _request: "ticket")
    result = await tool.invoke({"target": "."}, _context(tmp_path))
    assert result.status == ToolStatus.SUCCESS
    assert result.artifacts[0].artifact_id == "a" * 64
    assert result.data["coverage"]["complete"] is True
    assert result.data["input_manifest"][0]["path"] == "app.py"
    assert len(result.data["input_manifest_digest"]) == 64
    assert len(result.data["rule_bundle_digest"]) == 64
    result.evidence.append(
        Evidence(
            evidence_id="coverage-step",
            source="bandit_python_audit:sandbox-1",
            summary="bounded execution completed",
            metadata={"evidence_type": "execution_coverage"},
        )
    )
    assert deterministic_negative_coverage_complete(
        plan=[
            PlanStep(
                step_id="scan-bandit",
                objective="scan",
                agent_role="sast_specialist",
                capability="sast",
                tool_candidates=["bandit_python_audit"],
            )
        ],
        runtimes={
            "scan-bandit": StepRuntime(
                step_id="scan-bandit",
                status=StepStatus.SUCCEEDED,
                actual_tool_name="bandit_python_audit",
                observation_indexes=[0],
            )
        },
        observations=[result],
        findings=[],
        quarantined_finding_ids=set(),
    )
    await client.aclose()

    failures = [
        (httpx.Response(503), "SANDBOX_RUNNER_REJECTED"),
        (ValueError("bad"), "SANDBOX_RUNNER_UNAVAILABLE"),
    ]
    for response, expected in failures:

        async def failure(_request: httpx.Request, response: Any = response) -> httpx.Response:
            if isinstance(response, Exception):
                raise response
            return response

        client = httpx.AsyncClient(transport=httpx.MockTransport(failure))
        tool = SandboxBanditTool("http://runner", "token", client)
        result = await tool.invoke({"target": "."}, _context(tmp_path))
        assert result.error_code == expected
        await client.aclose()
    with pytest.raises(ValueError):
        SandboxBanditTool("", "")


async def test_sandbox_client_invalid_input_and_symlink(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(500))
    tool = SandboxBanditTool("http://runner", "token", httpx.AsyncClient(transport=transport))
    denied = await tool.invoke({"target": "../escape"}, _context(tmp_path))
    assert denied.status == ToolStatus.DENIED
    target = tmp_path / "target.py"
    target.write_text("pass", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except OSError:
        await tool._client.aclose()  # type: ignore[union-attr]
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symbolic"):
        tool._collect_files(link)
    await tool._client.aclose()  # type: ignore[union-attr]


def test_api_maps_sandbox_errors_and_validates_cancel() -> None:
    class BusyBackend:
        async def execute(self, _spec: Any, _invocation: Any) -> Any:
            raise SandboxError("RUNNER_BUSY", "busy")

        async def cleanup_orphans(self) -> int:
            return 0

        async def cancel(self, _invocation_id: str) -> bool:
            return False

    runner = SandboxRunner(BusyBackend(), {"bandit_python_audit": _spec()})
    with TestClient(create_sandbox_app(runner, "token", control_token="control")) as client:  # noqa: S106
        response = client.post(
            "/internal/v1/invocations",
            headers={"Authorization": "Bearer token"},
            json=_invocation().model_dump(mode="json"),
        )
        assert response.status_code == 429
        invalid = client.delete("/internal/v1/invocations/" + ("x" * 129), headers={"Authorization": "Bearer control"})
        assert invalid.status_code == 422


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("SECMIND_SANDBOX_TICKET_PUBLIC_KEY_FILE", "public key"),
        ("SECMIND_SANDBOX_STAGING_IMAGE", "staging"),
        ("SECMIND_SANDBOX_BANDIT_IMAGE", "tool images"),
        ("SECMIND_SANDBOX_CONTROL_TOKEN", "control token"),
        ("SECMIND_SANDBOX_DOCKER_HOST", "rootless"),
    ],
)
def test_production_app_fails_closed(monkeypatch: pytest.MonkeyPatch, missing: str, message: str) -> None:
    values = {
        "SECMIND_ENV": "competition",
        "SECMIND_SANDBOX_TICKET_PUBLIC_KEY_FILE": "key.pem",
        "SECMIND_SANDBOX_STAGING_IMAGE": "sha256:" + ("1" * 64),
        "SECMIND_SANDBOX_BANDIT_IMAGE": "sha256:" + ("2" * 64),
        "SECMIND_SANDBOX_CONTROL_TOKEN": "control",
        "SECMIND_SANDBOX_DOCKER_HOST": "unix:///run/user/1000/docker.sock",
    }
    values[missing] = ""
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(RuntimeError, match=message):
        create_production_app()


def test_development_app_defaults_to_a_writable_local_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def capture_app(_runner: Any, service_token: str | None = None, **_kwargs: Any) -> object:
        captured["service_token"] = service_token
        return object()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SECMIND_ENV", "development")
    monkeypatch.setenv("SECMIND_SANDBOX_TOKEN", "development-token")
    monkeypatch.delenv("SECMIND_ARTIFACT_ROOT", raising=False)
    monkeypatch.setattr("secmind.sandbox_api.create_sandbox_app", capture_app)
    create_production_app()
    assert (tmp_path / "data" / "sandbox-artifacts").is_dir()
    assert captured["service_token"] == "development-token"  # noqa: S105


def test_default_allowlist_adds_only_pinned_configured_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", "sha256:" + ("b" * 64))
    allowlist = default_allowlist()
    assert "semgrep_sast" in allowlist
    assert "gitleaks_secret_scan" not in allowlist
