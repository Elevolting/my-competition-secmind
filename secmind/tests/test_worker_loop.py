from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from secmind.agent_profiles import AgentProfileRegistry
from secmind.bounded_worker import BoundedWorker
from secmind.context_manager import MaterializedContext
from secmind.guardrail import Guardrail
from secmind.schemas import (
    AgentProfile,
    BudgetState,
    RiskLevel,
    Scenario,
    StepStatus,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
    WorkItem,
)
from secmind.tools import BaseTool, ToolBroker, ToolRegistry


class SequenceTool(BaseTool):
    def __init__(
        self,
        name: str,
        results: Iterable[ToolResult],
        *,
        idempotent: bool = True,
        risk: RiskLevel = RiskLevel.R1,
        evidence_types: list[str] | None = None,
    ) -> None:
        self.results = list(results)
        self.calls: list[tuple[dict[str, Any], ToolContext]] = []
        self.manifest = ToolManifest(
            name=name,
            version="1",
            description="bounded worker test tool",
            scenarios=[Scenario.CODE_AUDIT],
            input_schema={"type": "object"},
            output_schema={
                "type": "object",
                "properties": {"findings": {"type": "array"}},
                "required": ["findings"],
            },
            risk_level=risk,
            idempotent=idempotent,
            capability_tags=["sast"],
            evidence_types=evidence_types or ["finding"],
        )

    async def invoke(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        self.calls.append((dict(args), context.model_copy(deep=True)))
        index = min(len(self.calls) - 1, len(self.results) - 1)
        return self.results[index].model_copy(deep=True)


class FakeContextProvider:
    def __init__(self, *, token_estimate: int = 128) -> None:
        self.token_estimate = token_estimate
        self.requests = 0
        self.packs = {"pack-1", "pack-2"}

    def materialize(self, pack_id: str) -> MaterializedContext:
        if pack_id not in self.packs:
            raise KeyError(pack_id)
        return MaterializedContext(
            pack_id=pack_id,
            pack_digest="a" * 64,
            system_text="fixed policy",
            user_text="bounded task capsule",
            token_estimate=self.token_estimate,
        )

    def request_context(self, item: WorkItem, current_pack_id: str, reason: str) -> str | None:
        del item, current_pack_id, reason
        self.requests += 1
        return "pack-2"


def profile(*, max_turns: int = 3, max_tool_calls: int = 3, max_context_tokens: int = 1024) -> AgentProfile:
    return AgentProfile(
        profile_id="sast-profile",
        purpose="bounded SAST investigation",
        allowed_capabilities=["sast"],
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        max_context_tokens=max_context_tokens,
    )


def work_item(
    *,
    candidates: list[str] | None = None,
    capability: str = "sast",
    max_tool_calls: int = 3,
) -> WorkItem:
    return WorkItem(
        run_id="run-worker",
        step_id="scan",
        capability=capability,
        tool_name=(candidates or ["scanner"])[0],
        inputs={"target": "."},
        workspace_ref=".",
        context_pack_id="pack-1",
        capability_candidates=candidates or ["scanner"],
        agent_profile="sast-profile",
        transition_id="transition-1",
        lease_fence=7,
        lease_owner_id="worker-1",
        attempt=2,
        max_tool_calls=max_tool_calls,
        budget_reservation=BudgetState(),
    )


def worker_for(
    tools: list[BaseTool],
    context_provider: FakeContextProvider,
    *,
    worker_profile: AgentProfile | None = None,
) -> tuple[BoundedWorker, ToolBroker]:
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    broker = ToolBroker(registry, Guardrail())
    worker = BoundedWorker(
        broker=broker,
        profile_registry=AgentProfileRegistry([worker_profile or profile()]),
        context_provider=context_provider,
    )
    return worker, broker


@pytest.mark.asyncio
async def test_durable_worker_requires_a_signed_skill_binding() -> None:
    tool = SequenceTool("scanner", [ToolResult(status=ToolStatus.SUCCESS, data={"findings": []})])
    worker, broker = worker_for([tool], FakeContextProvider())
    durable = work_item().model_copy(
        update={
            "step_run_id": "step-run-1",
            "work_contract_id": "work-contract-1",
            "work_contract_digest": "a" * 64,
        }
    )
    try:
        rejected = await worker.run(durable)
        accepted = await worker.run(durable.model_copy(update={"skill_ids": ["python-security-audit"]}))
    finally:
        broker.close()

    assert rejected.typed_error == "SKILL_BINDING_REQUIRED"
    assert accepted.status == StepStatus.SUCCEEDED
    assert len(tool.calls) == 1


@pytest.mark.asyncio
async def test_worker_retries_idempotent_failure_and_preserves_attempt_and_fence() -> None:
    tool = SequenceTool(
        "scanner",
        [
            ToolResult(status=ToolStatus.TIMEOUT, error_code="TOOL_TIMEOUT"),
            ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}),
        ],
    )
    worker, broker = worker_for([tool], FakeContextProvider())
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.status == StepStatus.SUCCEEDED
    assert patch.attempt == 2
    assert patch.lease_fence == 7
    assert len(tool.calls) == 2
    assert tool.calls[0][1].idempotency_key != tool.calls[1][1].idempotency_key


@pytest.mark.asyncio
async def test_worker_item_tool_budget_prevents_ticketed_retry() -> None:
    tool = SequenceTool(
        "scanner",
        [
            ToolResult(status=ToolStatus.TIMEOUT, error_code="TOOL_TIMEOUT"),
            ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}),
        ],
    )
    worker, broker = worker_for([tool], FakeContextProvider())
    try:
        patch = await worker.run(work_item(max_tool_calls=1))
    finally:
        broker.close()

    assert patch.status == StepStatus.FAILED
    assert patch.typed_error == "WORKER_TOOL_BUDGET_EXHAUSTED"
    assert patch.actual_tool_calls == 1
    assert len(tool.calls) == 1


@pytest.mark.asyncio
async def test_worker_never_retries_non_idempotent_uncertain_result() -> None:
    tool = SequenceTool(
        "scanner",
        [ToolResult(status=ToolStatus.TIMEOUT, error_code="TOOL_TIMEOUT")],
        idempotent=False,
    )
    worker, broker = worker_for([tool], FakeContextProvider())
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.status == StepStatus.FAILED
    assert patch.typed_error == "RECOVERY_REQUIRED"
    assert len(tool.calls) == 1


@pytest.mark.asyncio
async def test_worker_allows_exactly_one_missing_context_refresh() -> None:
    tool = SequenceTool(
        "scanner",
        [
            ToolResult(status=ToolStatus.ERROR, error_code="MISSING_CONTEXT"),
            ToolResult(status=ToolStatus.SUCCESS, data={"findings": []}),
        ],
    )
    provider = FakeContextProvider()
    worker, broker = worker_for([tool], provider)
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.status == StepStatus.SUCCEEDED
    assert provider.requests == 1
    assert len(tool.calls) == 2


@pytest.mark.asyncio
async def test_second_missing_context_request_is_typed_terminal_failure() -> None:
    tool = SequenceTool(
        "scanner",
        [ToolResult(status=ToolStatus.ERROR, error_code="MISSING_CONTEXT")],
    )
    provider = FakeContextProvider()
    worker, broker = worker_for([tool], provider)
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.typed_error == "CONTEXT_REQUEST_LIMIT"
    assert provider.requests == 1
    assert len(tool.calls) == 2


@pytest.mark.asyncio
async def test_worker_enforces_three_turn_hard_limit() -> None:
    tool = SequenceTool(
        "scanner",
        [ToolResult(status=ToolStatus.ERROR, error_code="TRANSIENT")],
    )
    worker, broker = worker_for([tool], FakeContextProvider())
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.typed_error == "WORKER_MAX_TURNS"
    assert len(tool.calls) == 3


@pytest.mark.asyncio
async def test_worker_uses_only_approved_equivalent_fallback() -> None:
    unavailable = SequenceTool(
        "primary",
        [ToolResult(status=ToolStatus.ERROR, error_code="TOOL_UNAVAILABLE")],
        evidence_types=["finding"],
    )
    fallback = SequenceTool(
        "fallback",
        [ToolResult(status=ToolStatus.SUCCESS, data={"findings": []})],
        risk=RiskLevel.R0,
        evidence_types=["finding", "location"],
    )
    worker, broker = worker_for([unavailable, fallback], FakeContextProvider())
    try:
        patch = await worker.run(work_item(candidates=["primary", "fallback"]))
    finally:
        broker.close()

    assert patch.status == StepStatus.SUCCEEDED
    assert len(unavailable.calls) == 1
    assert len(fallback.calls) == 1


@pytest.mark.asyncio
async def test_worker_rejects_capability_and_context_budget_before_tool_boundary() -> None:
    tool = SequenceTool("scanner", [ToolResult(status=ToolStatus.SUCCESS, data={"findings": []})])
    provider = FakeContextProvider(token_estimate=513)
    worker, broker = worker_for([tool], provider, worker_profile=profile(max_context_tokens=512))
    try:
        denied_capability = await worker.run(work_item(capability="secret_scan"))
        denied_context = await worker.run(work_item())
    finally:
        broker.close()

    assert denied_capability.typed_error == "CAPABILITY_NOT_ALLOWED"
    assert denied_context.typed_error == "CONTEXT_BUDGET_EXCEEDED"
    assert tool.calls == []


@pytest.mark.asyncio
async def test_worker_rejects_malformed_normalized_finding() -> None:
    tool = SequenceTool(
        "scanner",
        [ToolResult(status=ToolStatus.SUCCESS, data={"findings": [{"rule_id": "missing-fields"}]})],
    )
    worker, broker = worker_for([tool], FakeContextProvider())
    try:
        patch = await worker.run(work_item())
    finally:
        broker.close()

    assert patch.typed_error == "INVALID_FINDING_OUTPUT"
    assert len(tool.calls) == 1
