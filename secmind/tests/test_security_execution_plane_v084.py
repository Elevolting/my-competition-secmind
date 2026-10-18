from __future__ import annotations

import asyncio
import base64
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from secmind.release_identity import (
    UNKNOWN,
    ReleaseIdentity,
    build_release_identity,
    component_digest,
    git_provenance,
    publishable_release_summary,
)
from secmind.sandbox import (
    MockSandboxBackend,
    SandboxArtifact,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxLog,
    SandboxResult,
    SandboxRunner,
    SandboxToolSpec,
)
from secmind.secret_scrubber import REDACTED, is_sensitive_key, scrub_text, scrub_value

IMAGE = "tool@sha256:" + ("a" * 64)


def _spec(**limits: int) -> SandboxToolSpec:
    return SandboxToolSpec(
        name="bandit_python_audit",
        image_digest=IMAGE,
        entrypoint=("run",),
        limits=SandboxLimits(**limits),
    )


def _invocation() -> SandboxInvocation:
    return SandboxInvocation(
        invocation_id="security-plane-invocation",
        tool_name="bandit_python_audit",
        files=[SandboxInputFile(path="app.py", content_base64=base64.b64encode(b"print(1)").decode())],
    )


def test_scrubber_covers_camel_pascal_and_nested_credential_names() -> None:
    source = {
        "apiKey": "api-secret",
        "ApiKey": "pascal-secret",
        "OAuthClientSecret": "oauth-secret",
        "nested": {
            "sessionToken": "session-secret",
            "privateKeyPem": "private-secret",
            "auth": {"refreshToken": "refresh-secret"},
        },
        "credentials": {"refreshToken": "refresh-secret"},
        "secretary": "not-secret",
        "tokenizer": "not-secret",
    }

    scrubbed = scrub_value(source)

    assert scrubbed["apiKey"] == REDACTED
    assert scrubbed["ApiKey"] == REDACTED
    assert scrubbed["OAuthClientSecret"] == REDACTED
    assert scrubbed["nested"] == {
        "sessionToken": REDACTED,
        "privateKeyPem": REDACTED,
        "auth": {"refreshToken": REDACTED},
    }
    assert scrubbed["credentials"] == REDACTED
    assert scrubbed["secretary"] == "not-secret"
    assert scrubbed["tokenizer"] == "not-secret"
    assert is_sensitive_key("OAuthClientSecret")
    raw = '"apiKey":"api-secret", "OAuthClientSecret":"oauth-secret"'
    assert "api-secret" not in scrub_text(raw)
    assert "oauth-secret" not in scrub_text(raw)


def test_runner_rejects_resource_and_artifact_limit_overrides() -> None:
    with pytest.raises(ValueError):
        SandboxLimits(memory_bytes=0)
    with pytest.raises(ValueError):
        SandboxLimits(max_artifacts=SandboxLimits().max_artifacts + 1)

    class OversizedBackend(MockSandboxBackend):
        async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
            content = b"1234"
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

    runner = SandboxRunner(OversizedBackend(), {"bandit_python_audit": _spec(max_output_bytes=3)})
    with pytest.raises(SandboxError) as error:
        asyncio.run(runner.execute(_invocation()))
    assert error.value.code == "OUTPUT_TOO_LARGE"


@pytest.mark.asyncio
async def test_runner_cancel_denies_late_result() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class WaitingBackend(MockSandboxBackend):
        async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
            started.set()
            await release.wait()
            return await super().execute(spec, invocation)

        async def cancel(self, invocation_id: str) -> bool:
            release.set()
            return await super().cancel(invocation_id)

    backend = WaitingBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": _spec()})
    task = asyncio.create_task(runner.execute(_invocation()))
    await started.wait()
    assert await runner.cancel("security-plane-invocation")
    with pytest.raises(SandboxError, match="cancelled") as error:
        await task
    assert error.value.code == "SANDBOX_CANCELLED"


@pytest.mark.asyncio
async def test_runner_rejects_result_from_superseded_lease_fence() -> None:
    release_old = asyncio.Event()
    release_new = asyncio.Event()

    class FencedBackend(MockSandboxBackend):
        async def execute(self, spec: SandboxToolSpec, invocation: SandboxInvocation) -> SandboxResult:
            await (release_old if invocation.lease_fence == 1 else release_new).wait()
            return await super().execute(spec, invocation)

    def request(invocation_id: str, fence: int) -> SandboxInvocation:
        return _invocation().model_copy(
            update={"invocation_id": invocation_id, "run_id": "fenced-run", "lease_fence": fence}
        )

    backend = FencedBackend()
    runner = SandboxRunner(backend, {"bandit_python_audit": _spec()}, max_parallelism=2)
    old = asyncio.create_task(runner.execute(request("old", 1)))
    await asyncio.sleep(0)
    new = asyncio.create_task(runner.execute(request("new", 2)))
    await asyncio.sleep(0)
    release_new.set()
    assert (await new).status == "success"
    release_old.set()
    with pytest.raises(SandboxError) as stale:
        await old
    assert stale.value.code == "STALE_FENCE"


def test_release_identity_is_digest_only_and_binds_git_tree(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required to verify Git provenance")
    repository = tmp_path / "repository"
    repository.mkdir()
    for args in (
        ("init", "-q"),
        ("config", "user.name", "Release Identity Test"),
        ("config", "user.email", "release-identity@example.invalid"),
    ):
        subprocess.run([git, *args], cwd=repository, check=True, capture_output=True)  # noqa: S603
    (repository / "source.py").write_text("print('release')\n", encoding="utf-8")
    for args in (("add", "source.py"), ("commit", "-q", "-m", "test release")):
        subprocess.run([git, *args], cwd=repository, check=True, capture_output=True)  # noqa: S603
    identity = build_release_identity(
        repository,
        version="0.8.4",
        config={"secret": "never serialized"},
        prompt="fixed prompt",
        rules={"rule": "fixed"},
        bridge=b"bridge summary",
    )
    payload = identity.to_dict()

    assert payload["version"] == "0.8.4"
    assert len(payload["git_commit"]) == 40
    assert len(payload["git_tree"]) == 40
    assert identity.dirty is git_provenance(repository)[2]
    for field in ("config_digest", "prompt_digest", "rule_digest", "bridge_digest", "identity_digest"):
        assert len(payload[field]) == 64
    assert "never serialized" not in repr(payload)
    assert component_digest({"a": 1, "b": 2}) == component_digest({"b": 2, "a": 1})
    round_trip = ReleaseIdentity(**{key: value for key, value in payload.items() if key != "identity_digest"})
    assert round_trip.identity_digest == identity.identity_digest
    assert publishable_release_summary(repository)["identity_digest"]


def test_release_identity_without_git_provenance_is_explicit(tmp_path: Path) -> None:
    identity = build_release_identity(tmp_path, version="0.8.4")
    assert identity.git_commit == UNKNOWN
    assert identity.git_tree == UNKNOWN
    assert identity.dirty is True
    assert len(identity.identity_digest) == 64
