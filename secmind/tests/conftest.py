from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.config import Settings
from secmind.quarantine import FailureCapsuleStore
from secmind.schemas import AgentState
from secmind.task_contract import compile_resolved_task_contract


def pytest_asyncio_loop_factories(config, item):
    """Select a Windows loop per test without mutating global policy.

    Psycopg's async implementation needs a selector loop, while the builtin
    subprocess tools need a Proactor loop.  pytest-asyncio 1.3 exposes this
    hook specifically for per-item loop factories; keeping the choice here
    prevents collection-time imports from contaminating unrelated tests.
    """

    del config
    if sys.platform != "win32":
        return {"default": asyncio.new_event_loop}
    if "integration" in item.keywords:
        return {"selector": asyncio.SelectorEventLoop}
    return {"proactor": asyncio.ProactorEventLoop}


@pytest.fixture
def admission_stores(tmp_path: Path) -> tuple[ContentAddressedArtifactStore, FailureCapsuleStore]:
    """Provide real isolated CAS/capsule stores for direct admission tests."""

    return (
        ContentAddressedArtifactStore(tmp_path / "admission-artifacts"),
        FailureCapsuleStore(tmp_path / "admission-capsules"),
    )


def seal_execution_contract(state: AgentState) -> AgentState:
    """Attach a deterministic trusted execution contract to a direct-node test state."""

    task = state.task
    scenario = state.scenario.value
    manifest_payload = [
        {"path": item.relative_path.replace("\\", "/"), "sha256": item.sha256.lower()}
        for item in sorted(state.input_artifacts, key=lambda item: item.relative_path.casefold())
    ]
    manifest_digest = hashlib.sha256(
        json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    task_spec_ref = state.task_spec_ref
    spec_payload = {
        "task_spec_id": task_spec_ref.task_spec_id if task_spec_ref is not None else f"test-spec-{state.run_id}",
        "run_id": state.run_id,
        "revision": task_spec_ref.revision if task_spec_ref is not None else 1,
        "content_digest": (
            task_spec_ref.content_digest
            if task_spec_ref is not None
            else hashlib.sha256(f"test-spec:{state.run_id}".encode()).hexdigest()
        ),
        "objectives": [task.objective],
        "primary_scenario": scenario,
        "primary_domain": task.primary_domain,
        "secondary_scenarios": [],
        "secondary_capabilities": list(task.secondary_capabilities),
        "scoring_mode": task.scoring_mode,
        "interaction_mode": task.interaction_mode,
        "autonomy_policy": task.autonomy_policy,
        "authorized_scope": list(task.target_scope),
        "constraints": list(task.constraints),
        "prohibited_actions": [],
        "expected_outputs": list(task.expected_outputs),
        "success_criteria": [],
        "output_contract": dict(task.output_contract),
        "asset_ids": [item.artifact_id for item in state.input_artifacts],
    }
    state.resolved_task_contract = compile_resolved_task_contract(
        spec_payload,
        input_manifest_digest=manifest_digest,
    )
    return state


@pytest.fixture(autouse=True)
def isolate_model_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make offline/mock the only provider modes capable of running in pytest."""

    monkeypatch.setenv("SECMIND_MODEL_MODE", "offline")
    monkeypatch.setenv("SECMIND_ALLOW_LIVE_MODELS", "false")
    for name in (
        "SECMIND_QWEN_API_KEY",
        "SECMIND_DEEPSEEK_API_KEY",
        "SECMIND_OPENAI_API_KEY",
        "DASHSCOPE_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.setenv(name, "")

    real_async_http = httpx.AsyncHTTPTransport.handle_async_request

    async def deny_real_model_http(
        _transport: httpx.AsyncHTTPTransport,
        request: httpx.Request,
    ) -> httpx.Response:
        endpoint = request.url.path.rstrip("/")
        if endpoint.endswith(("/chat/completions", "/embeddings")):
            raise AssertionError("pytest attempted real model HTTP; inject httpx.MockTransport")
        return await real_async_http(_transport, request)

    # MockTransport and ASGI transports do not traverse this method. Provider
    # endpoints on an accidentally owned client fail before DNS, while tests
    # may still exercise failure handling for local Runner URLs.
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_real_model_http)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        demo_mode=True,
        model_mode="offline",
        allow_live_models=False,
        model_base_url_provider="auto",
        qwen_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        trusted_model_base_urls="https://dashscope.aliyuncs.com/compatible-mode/v1",
        qwen_api_key="",
        deepseek_api_key="",
        openai_api_key="",
        planner_model="qwen-plus",
        worker_model="qwen-turbo",
        fallback_model="qwen-turbo",
        embedding_model="text-embedding-v3",
        model_structured_output_mode="auto",
        sandbox_runner_url="",
        sandbox_token="",
        sandbox_control_token="",
        sandbox_ticket_private_key_file=None,
        unsafe_development_tools=True,
        enable_api_dynamic_probes=False,
        database_url=f"sqlite:///{(tmp_path / 'secmind.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        max_upload_bytes=1024 * 1024,
        max_extracted_bytes=2 * 1024 * 1024,
    )
