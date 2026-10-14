from __future__ import annotations

from typing import Any

import pytest

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.execution import ExecutionConflict, ExecutionStore
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerDedupeConflict, LedgerStore
from secmind.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    ArtifactRef,
    DataView,
    Evidence,
    RiskLevel,
    Scenario,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
)
from secmind.secret_scrubber import REDACTED
from secmind.tools import BaseTool, ToolBroker, ToolRegistry


class CountingTool(BaseTool):
    def __init__(self, risk: RiskLevel = RiskLevel.R1, *, idempotent: bool = True) -> None:
        self.calls = 0
        self.manifest = ToolManifest(
            name="counter",
            version="1",
            description="test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
            },
            risk_level=risk,
            idempotent=idempotent,
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        self.calls += 1
        return ToolResult(status=ToolStatus.SUCCESS, data={"count": self.calls})


class ArtifactTool(CountingTool):
    def __init__(self, artifact_store: ContentAddressedArtifactStore) -> None:
        super().__init__()
        self.artifact_store = artifact_store

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        stored = self.artifact_store.put(b"api_key=synthetic-secret", media_type="text/plain")
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={
                "count": 1,
                "artifact_digest": stored.sha256,
                "artifact_id": stored.artifact_id,
                "api_key": "synthetic-secret",
            },
            artifacts=[
                ArtifactRef(
                    artifact_id=stored.artifact_id,
                    ref=stored.artifact_id,
                    sha256=stored.sha256,
                    size_bytes=stored.size_bytes,
                    media_type=stored.media_type,
                )
            ],
            evidence=[
                Evidence(
                    source="artifact-tool",
                    summary="bounded test evidence",
                    metadata={"artifact_digest": stored.sha256, "api_key": "synthetic-secret"},
                )
            ],
        )


class MismatchedInvocationTool(CountingTool):
    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        return ToolResult(
            invocation_id="another-invocation",
            status=ToolStatus.SUCCESS,
            data={"count": 1},
        )


class PublicFindingTool(CountingTool):
    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        self.calls += 1
        evidence_id = "evidence-c4bf6edb7cb1ee36937d82a7"
        relative_path = "7ec65389-e32b-413e-a0e5-44a574c9dd84-vulnerable_app.py"
        return ToolResult(
            status=ToolStatus.SUCCESS,
            data={
                "count": 1,
                "findings": [
                    {
                        "finding_id": "finding-c4bf6edb7cb1ee36937d82a712345678",
                        "rule_id": "CWE-78",
                        "path": relative_path,
                        "line": 8,
                        "evidence_ids": [evidence_id],
                        "api_key": "synthetic-secret",
                    }
                ],
            },
            evidence=[
                Evidence(
                    evidence_id=evidence_id,
                    source="bandit:1.7.8",
                    summary="B602/CWE-78 finding",
                    metadata={"path": relative_path, "api_key": "synthetic-secret"},
                )
            ],
        )


def context(*, key: str = "logical-call") -> ToolContext:
    return ToolContext(
        run_id="run-1",
        step_id="step-1",
        workspace=".",
        allowed_paths=["."],
        idempotency_key=key,
    )


def broker_for(tool: BaseTool, tmp_path) -> tuple[ToolBroker, ExecutionStore, LedgerStore]:
    registry = ToolRegistry()
    registry.register(tool)
    execution = ExecutionStore(f"sqlite:///{tmp_path / 'execution.db'}")
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger.db'}")
    return ToolBroker(registry, Guardrail(), execution, ledger), execution, ledger


@pytest.mark.asyncio
async def test_atomic_broker_validates_and_deduplicates(tmp_path) -> None:
    tool = CountingTool()
    broker, _, ledger = broker_for(tool, tmp_path)
    invalid = await broker.execute("counter", {"unexpected": True}, context(key="invalid"))
    assert invalid.status == ToolStatus.DENIED
    assert invalid.error_code == "TOOL_INPUT_INVALID"

    first = await broker.execute("counter", {"target": "."}, context())
    second = await broker.execute("counter", {"target": "."}, context())
    assert first.status == second.status == ToolStatus.SUCCESS
    assert first.invocation_id == second.invocation_id
    assert tool.calls == 1
    assert [event.event_type for event in ledger.events("run-1")] == ["tool.started", "tool.completed"]


@pytest.mark.asyncio
async def test_atomic_broker_rejects_tool_result_from_another_invocation(tmp_path) -> None:
    broker, _, ledger = broker_for(MismatchedInvocationTool(), tmp_path)
    tool_context = context(key="mismatch")

    result = await broker.execute("counter", {"target": "."}, tool_context)

    assert result.status == ToolStatus.ERROR
    assert result.error_code == "TOOL_INVOCATION_MISMATCH"
    assert result.invocation_id == tool_context.invocation_id
    assert [event.event_type for event in ledger.events("run-1")] == ["tool.started", "tool.failed"]


@pytest.mark.asyncio
async def test_atomic_broker_preserves_public_finding_identity_and_upload_path(tmp_path) -> None:
    tool = PublicFindingTool()
    broker, _, _ = broker_for(tool, tmp_path)

    first = await broker.execute("counter", {"target": "."}, context(key="public-finding"))
    replay = await broker.execute("counter", {"target": "."}, context(key="public-finding"))

    expected_id = "evidence-c4bf6edb7cb1ee36937d82a7"
    expected_path = "7ec65389-e32b-413e-a0e5-44a574c9dd84-vulnerable_app.py"
    assert first.evidence[0].evidence_id == replay.evidence[0].evidence_id == expected_id
    assert first.evidence[0].metadata["path"] == replay.evidence[0].metadata["path"] == expected_path
    assert first.data["findings"][0]["path"] == replay.data["findings"][0]["path"] == expected_path
    assert first.data["findings"][0]["evidence_ids"] == replay.data["findings"][0]["evidence_ids"] == [expected_id]
    assert first.data["findings"][0]["api_key"] == REDACTED
    assert first.evidence[0].metadata["api_key"] == REDACTED
    assert tool.calls == 1


@pytest.mark.asyncio
async def test_runner_artifacts_remain_raw_until_server_owned_projection(tmp_path) -> None:
    artifact_store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    tool = ArtifactTool(artifact_store)
    registry = ToolRegistry()
    registry.register(tool)
    broker = ToolBroker(
        registry,
        Guardrail(),
        artifact_store=artifact_store,
    )

    result = await broker.execute("counter", {"target": "."}, context(key="artifact-result"))

    assert result.status == ToolStatus.SUCCESS
    assert result.data["artifact_digest"] == next(
        item.sha256 for item in result.artifacts if item.media_type == "text/plain"
    )
    assert result.data["artifact_id"] == REDACTED
    assert result.data["api_key"] == REDACTED
    raw = next(item for item in result.artifacts if item.media_type == "text/plain")
    raw_metadata = artifact_store.metadata_for(raw.artifact_id)
    assert raw_metadata.data_view == DataView.RAW_RESTRICTED
    assert raw_metadata.run_ids == ("run-1",)
    evidence_artifact = next(item for item in result.artifacts if item.media_type.endswith("evidence+json"))
    assert result.evidence[0].artifact_ref == evidence_artifact.artifact_id
    assert result.evidence[0].metadata["artifact_digest"] == raw.sha256
    assert result.evidence[0].metadata["api_key"] == REDACTED
    evidence_metadata = artifact_store.metadata_for(evidence_artifact.artifact_id)
    assert evidence_metadata.data_view == DataView.OBSERVABLE
    assert evidence_metadata.run_ids == ("run-1",)


@pytest.mark.asyncio
async def test_r2_requires_matching_durable_approval(tmp_path) -> None:
    tool = CountingTool(RiskLevel.R2)
    broker, store, _ = broker_for(tool, tmp_path)
    args = {"target": "."}
    request = ApprovalRequest(
        request_id="approval-1",
        run_id="run-1",
        step_id="step-1",
        tool_name="counter",
        parameters=args,
        target=".",
        risk_level=RiskLevel.R2,
        reason="network-like test operation",
        expected_impact="read only",
    )
    store.register_approval(request)
    denied = await broker.execute("counter", args, context(), approval_request_id=request.request_id)
    assert denied.error_code == "APPROVAL_REQUIRED"

    response = ApprovalResponse(decision=ApprovalDecision.APPROVE, reason="authorized")
    store.resolve_approval(request.request_id, response)
    store.resolve_approval(request.request_id, response)
    allowed = await broker.execute("counter", args, context(), approval_request_id=request.request_id)
    assert allowed.status == ToolStatus.SUCCESS
    with pytest.raises(ExecutionConflict):
        store.resolve_approval(request.request_id, ApprovalResponse(decision=ApprovalDecision.DENY))


@pytest.mark.asyncio
async def test_edited_approval_only_authorizes_edited_parameters(tmp_path) -> None:
    tool = CountingTool(RiskLevel.R2)
    broker, store, _ = broker_for(tool, tmp_path)
    request = ApprovalRequest(
        request_id="approval-edit",
        run_id="run-1",
        step_id="step-1",
        tool_name="counter",
        parameters={"target": "original"},
        target="original",
        risk_level=RiskLevel.R2,
        reason="test",
        expected_impact="read only",
    )
    store.register_approval(request)
    store.resolve_approval(
        request.request_id,
        ApprovalResponse(decision=ApprovalDecision.EDIT, edited_parameters={"target": "edited"}),
    )
    original = await broker.execute(
        "counter", {"target": "original"}, context(key="original"), approval_request_id=request.request_id
    )
    edited = await broker.execute(
        "counter", {"target": "edited"}, context(key="edited"), approval_request_id=request.request_id
    )
    assert original.error_code == "APPROVAL_REQUIRED"
    assert edited.status == ToolStatus.SUCCESS


def test_ledger_dedupe_key_rejects_conflicting_payload(tmp_path) -> None:
    ledger = LedgerStore(f"sqlite:///{tmp_path / 'ledger-dedupe.db'}")
    first = ledger.append("run", "event", {"value": 1}, dedupe_key="stable-key")
    repeated = ledger.append("run", "event", {"value": 1}, dedupe_key="stable-key")
    assert repeated == first
    with pytest.raises(LedgerDedupeConflict):
        ledger.append("run", "event", {"value": 999}, dedupe_key="stable-key")
    assert len(ledger.events("run")) == 1
    assert ledger.verify("run")
