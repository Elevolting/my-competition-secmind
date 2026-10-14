from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy.orm import Session

from secmind.config import Settings
from secmind.coordinator import CoordinatorStore, ModelInvocationRow, OutboxEventRow
from secmind.investigation.contracts import (
    ReservationStatus,
    UsageReservation,
    UsageSettlement,
    seal_contract,
)
from secmind.investigation.store import (
    InvestigationConflict,
    InvestigationStore,
    UsageReservationRow,
)
from secmind.llm import ModelGatewayError, ProviderAttempt, QwenGateway
from secmind.model_router import MODEL_ROUTER_VERSION
from secmind.prompting import PromptCompiler, PromptContext, PromptRole
from secmind.schemas import ModelUsage


def test_aggregate_usage_accepts_partial_cache_classification() -> None:
    usage = ModelUsage.model_validate({
        "provider_requests": 2,
        "input_tokens": 18_997,
        "output_tokens": 20_874,
        "cache_hit_input_tokens": 0,
        "cache_miss_input_tokens": 6_294,
    })
    assert usage.cache_miss_input_tokens == 6_294
    with pytest.raises(ValueError, match="cannot exceed input tokens"):
        ModelUsage(input_tokens=10, cache_hit_input_tokens=11)


class _Answer(BaseModel):
    answer: str


class _FailingSettlementStore:
    """Minimal fault-injection boundary used without network or a real DB."""

    def __init__(self) -> None:
        self.reservations: list[UsageReservation] = []
        self.settlements: list[UsageSettlement] = []

    def reserve_usage(self, reservation: UsageReservation) -> UsageReservation:
        self.reservations.append(reservation)
        return reservation

    def settle_usage(self, settlement: UsageSettlement) -> UsageSettlement:
        self.settlements.append(settlement)
        raise InvestigationConflict("injected accounting outage")


def _settings() -> Settings:
    return Settings(
        demo_mode=False,
        model_mode="mock",
        allow_live_models=False,
        trusted_model_base_urls="https://dashscope.aliyuncs.com/compatible-mode/v1",
        qwen_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        planner_model="qwen-plus",
        worker_model="qwen-plus",
        fallback_model="qwen-plus",
        model_max_attempts=1,
        model_structured_repair_attempts=0,
        model_max_output_tokens=256,
        max_provider_requests=20,
        max_input_tokens=100_000,
        max_output_tokens=10_000,
        max_cost_units=10,
    )


def _sealed_reservation(**values: Any) -> UsageReservation:
    return seal_contract(UsageReservation, digest_field="content_digest", **values)


def _sealed_settlement(**values: Any) -> UsageSettlement:
    return seal_contract(UsageSettlement, digest_field="receipt_digest", **values)


def _status(store: InvestigationStore, reservation_id: str) -> str:
    with Session(store.engine) as session:
        row = session.get(UsageReservationRow, reservation_id)
        assert row is not None
    return row.status


def test_coordinator_persists_nonzero_provider_cost() -> None:
    coordinator = CoordinatorStore("sqlite:///:memory:")
    try:
        attempt = ProviderAttempt(
            provider_request_id="provider-cost-1",
            sequence=1,
            model_id="qwen-plus",
            endpoint="chat/completions",
            duration_ms=12,
            status_code=200,
            succeeded=True,
            retryable=False,
            error_type=None,
            usage=ModelUsage(
                provider_requests=1,
                input_tokens=100,
                output_tokens=20,
                cost_units=0.00048,
            ),
            provider_request_sha256="a" * 64,
            task_kind="planning",
            lane="reasoning",
            router_version=MODEL_ROUTER_VERSION,
            prompt_version="test-prompt-v1",
            prompt_artifact_id="c" * 64,
            prompt_selection_digest="d" * 64,
            prompt_optimizer_attempt_id="prompt-opt-test",
            prompt_lineage_reason="optimizer_completed",
            parent_logical_call_id="parent-logical-cost",
            ordinal=2,
            lineage_stage="fallback",
            response_sha256="b" * 64,
            run_id="run-cost",
            logical_call_id="logical-cost",
        )
        coordinator.record_model_attempts("run-cost", [attempt])
        coordinator.record_model_attempts("run-cost", [attempt])
        with Session(coordinator.engine) as session:
            row = session.query(ModelInvocationRow).one()
            assert row.cost_microunits == 480
            assert row.request_hash == "a" * 64
            assert (row.task_kind, row.model_lane, row.router_version) == (
                "planning",
                "reasoning",
                MODEL_ROUTER_VERSION,
            )
            assert (row.prompt_version, row.response_hash) == ("test-prompt-v1", "b" * 64)
            assert (row.prompt_artifact_id, row.prompt_selection_digest) == ("c" * 64, "d" * 64)
            assert (
                row.logical_call_id,
                row.parent_logical_call_id,
                row.prompt_optimizer_attempt_id,
                row.prompt_lineage_reason,
                row.lineage_stage,
                row.attempt_ordinal,
            ) == ("logical-cost", "parent-logical-cost", "prompt-opt-test", "optimizer_completed", "fallback", 2)
            event = session.query(OutboxEventRow).one()
            payload = json.loads(event.payload_json)
            assert event.transition_id == "model-attempt:provider-cost-1"
            assert event.event_type == "model.attempt_recorded"
            assert event.actor == "model_gateway"
            assert payload["request_hash"] == "a" * 64
            assert (payload["task_kind"], payload["lane"], payload["router_version"]) == (
                "planning",
                "reasoning",
                MODEL_ROUTER_VERSION,
            )
            assert (payload["prompt_version"], payload["response_hash"]) == ("test-prompt-v1", "b" * 64)
            assert (payload["prompt_artifact_id"], payload["prompt_selection_digest"]) == (
                "c" * 64,
                "d" * 64,
            )
            assert (
                payload["logical_call_id"],
                payload["parent_logical_call_id"],
                payload["prompt_optimizer_attempt_id"],
                payload["prompt_lineage_reason"],
                payload["lineage_stage"],
                payload["attempt_ordinal"],
            ) == ("logical-cost", "parent-logical-cost", "prompt-opt-test", "optimizer_completed", "fallback", 2)
    finally:
        coordinator.close()


def test_coordinator_normalizes_legacy_attempt_lineage() -> None:
    coordinator = CoordinatorStore("sqlite:///:memory:")
    try:
        attempt = ProviderAttempt(
            provider_request_id="provider-legacy-lineage",
            sequence=1,
            model_id="qwen-plus",
            endpoint="chat/completions",
            duration_ms=1,
            status_code=200,
            succeeded=True,
            retryable=False,
            error_type=None,
            usage=ModelUsage(provider_requests=1, input_tokens=2, output_tokens=1),
            provider_request_sha256="e" * 64,
            task_kind="planning",
            lane="reasoning",
            router_version=MODEL_ROUTER_VERSION,
            prompt_version="legacy-prompt-v1",
            response_sha256="f" * 64,
            run_id="run-legacy-lineage",
        )
        coordinator.record_model_attempts("run-legacy-lineage", [attempt])
        with Session(coordinator.engine) as session:
            row = session.query(ModelInvocationRow).one()
            assert row.logical_call_id
            assert row.parent_logical_call_id == row.logical_call_id
            assert row.prompt_selection_digest and len(row.prompt_selection_digest) == 64
            assert row.prompt_lineage_reason == "legacy_unbound_prompt"
            assert row.lineage_stage == "legacy"
            assert row.attempt_ordinal == 1
    finally:
        coordinator.close()


@pytest.mark.asyncio
async def test_gateway_binds_fixed_prompt_artifact_to_provider_attempt() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "bound"})}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )

    context = PromptContext.create(
        run_id="run-artifact-lineage",
        role=PromptRole.PRIMARY,
        phase="direct_first_primary",
        languages=("python",),
        capability_profile="code-audit",
        token_budget=4096,
        deadline_remaining_ms=30_000,
        trusted_feature_digest="a" * 64,
        scope_digest="b" * 64,
        output_schema_ref="secmind://prompt-schemas/test-answer",
    )
    artifact = PromptCompiler().compile_fixed(
        context=context,
        output_model=_Answer,
        system_prompt="Return a bounded answer.",
        prompt_version="fixed-lineage-v1",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(_settings(), client)
    try:
        output, meta = await gateway.structured(
            role="primary",
            system_prompt="ignored",
            user_prompt="answer",
            output_model=_Answer,
            prompt_version="ignored",
            run_id=context.run_id,
            prompt_artifact=artifact,
        )
        assert output.answer == "bound"
        attempt = gateway.provider_attempts[-1]
        assert attempt.prompt_artifact_id == artifact.artifact_id
        assert attempt.prompt_selection_digest == artifact.selection_digest
        assert attempt.prompt_optimizer_attempt_id is None
        assert attempt.prompt_lineage_reason == "fixed_mode"
        assert attempt.logical_call_id == meta.logical_call_id
        assert attempt.parent_logical_call_id == meta.parent_logical_call_id == meta.logical_call_id
        assert attempt.ordinal == 1
        assert attempt.lineage_stage == "primary"
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_gateway_does_not_replay_schema_failure_to_same_provider() -> None:
    responses = iter(
        (
            {"answer": 7},
            {"answer": "repaired"},
        )
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(next(responses))}}]})

    settings = _settings()
    settings.model_structured_repair_attempts = 1
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(settings, client)
    try:
        with pytest.raises(ModelGatewayError):
            await gateway.structured(
                role="planner",
                system_prompt="Return a bounded answer.",
                user_prompt="answer",
                output_model=_Answer,
                prompt_version="repair-lineage-v1",
            )
        assert [attempt.lineage_stage for attempt in gateway.provider_attempts] == ["primary"]
        assert [attempt.ordinal for attempt in gateway.provider_attempts] == [1]
        assert all(attempt.parent_logical_call_id for attempt in gateway.provider_attempts)
    finally:
        await gateway.close()


def test_model_attempt_outbox_order_uses_stable_causal_subsequences() -> None:
    coordinator = CoordinatorStore("sqlite:///:memory:")
    attempts = [
        ProviderAttempt(
            provider_request_id=f"provider-order-{sequence}",
            sequence=sequence,
            model_id="qwen-plus",
            endpoint="chat",
            duration_ms=sequence,
            status_code=200,
            succeeded=True,
            retryable=False,
            error_type=None,
            usage=ModelUsage(provider_requests=1),
            provider_request_sha256=f"{sequence:064x}",
            task_kind="planning",
            lane="reasoning",
            router_version=MODEL_ROUTER_VERSION,
            prompt_version="order-v1",
            response_sha256=f"{sequence + 10:064x}",
            run_id="run-order",
        )
        for sequence in range(1, 5)
    ]
    try:
        coordinator.record_model_attempts("run-order", list(reversed(attempts)))
        coordinator.record_model_attempts("run-order", attempts)
        with Session(coordinator.engine) as session:
            rows = (
                session.query(OutboxEventRow)
                .order_by(
                    OutboxEventRow.transition_ordinal,
                    OutboxEventRow.subsequence,
                    OutboxEventRow.created_at,
                    OutboxEventRow.outbox_id,
                )
                .all()
            )
        assert [json.loads(row.payload_json)["attempt_sequence"] for row in rows] == [1, 2, 3, 4]
        assert [row.subsequence for row in rows] == [1, 2, 3, 4]
    finally:
        coordinator.close()


def test_wall_time_is_diagnostic_and_never_rejects_settlement() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="root",
                run_id="run-wall",
                transition_id="root",
                kind="run",
                provider_requests=10,
                input_tokens=100,
                output_tokens=100,
                cost_units=10,
                # A deadline-like value must not be divided or summed across
                # child requests.
                wall_time_ms=1,
            )
        )
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="child",
                run_id="run-wall",
                parent_reservation_id="root",
                transition_id="model:child",
                kind="model",
                provider_requests=1,
                input_tokens=10,
                output_tokens=10,
                cost_units=1,
                wall_time_ms=10_000,
            )
        )

        receipt = store.settle_usage(
            _sealed_settlement(
                reservation_id="child",
                run_id="run-wall",
                model_invocation_ids=["provider-1"],
                provider_requests=1,
                input_tokens=8,
                output_tokens=4,
                cost_units=0.1,
                wall_time_ms=999_999,
            )
        )

        assert receipt.wall_time_ms == 999_999
        assert _status(store, "child") == ReservationStatus.SETTLED.value
        assert store.unsettled_reservation_ids("run-wall") == []
        assert store.settled_provider_usage("run-wall") == ModelUsage(
            provider_requests=1,
            input_tokens=8,
            output_tokens=4,
            cost_units=0.1,
        )
    finally:
        store.close()


def test_provider_usage_excludes_aggregate_model_step_envelopes() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="root",
                run_id="run-aggregate",
                transition_id="root",
                kind="run",
                provider_requests=10,
                input_tokens=1_000,
                output_tokens=1_000,
                cost_units=10,
            )
        )
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="provider-child",
                run_id="run-aggregate",
                parent_reservation_id="root",
                transition_id="model:provider-child",
                kind="model",
                provider_requests=1,
                input_tokens=100,
                output_tokens=100,
                cost_units=1,
            )
        )
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="step-envelope",
                run_id="run-aggregate",
                transition_id="step:model-source-review",
                kind="model",
                provider_requests=1,
                input_tokens=100,
                output_tokens=100,
                cost_units=1,
            )
        )
        for reservation_id in ("provider-child", "step-envelope"):
            store.settle_usage(
                _sealed_settlement(
                    reservation_id=reservation_id,
                    run_id="run-aggregate",
                    provider_requests=1,
                    input_tokens=12,
                    output_tokens=3,
                    cost_units=0.2,
                )
            )

        assert store.settled_provider_usage("run-aggregate") == ModelUsage(
            provider_requests=1,
            input_tokens=12,
            output_tokens=3,
            cost_units=0.2,
        )
    finally:
        store.close()


def test_additive_overage_is_recorded_as_terminal_overspent() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="root",
                run_id="run-over",
                transition_id="root",
                kind="run",
                provider_requests=10,
                input_tokens=100,
                output_tokens=100,
                cost_units=10,
            )
        )
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="child",
                run_id="run-over",
                parent_reservation_id="root",
                transition_id="model:child",
                kind="model",
                provider_requests=1,
                input_tokens=1,
                output_tokens=1,
                cost_units=0.01,
            )
        )

        store.settle_usage(
            _sealed_settlement(
                reservation_id="child",
                run_id="run-over",
                model_invocation_ids=["provider-1"],
                provider_requests=1,
                input_tokens=2,
                output_tokens=1,
                cost_units=0.02,
            )
        )

        assert _status(store, "child") == ReservationStatus.OVERSPENT.value
        assert store.unsettled_reservation_ids("run-over") == []
    finally:
        store.close()


def test_late_receipt_reconciles_a_released_reservation() -> None:
    store = InvestigationStore("sqlite:///:memory:")
    try:
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="root",
                run_id="run-late",
                transition_id="root",
                kind="run",
                provider_requests=10,
                input_tokens=100,
                output_tokens=100,
                cost_units=10,
            )
        )
        store.reserve_usage(
            _sealed_reservation(
                reservation_id="child",
                run_id="run-late",
                parent_reservation_id="root",
                transition_id="model:child",
                kind="model",
                provider_requests=1,
                input_tokens=10,
                output_tokens=10,
                cost_units=1,
            )
        )
        store.release_usage("child", run_id="run-late")

        store.settle_usage(
            _sealed_settlement(
                reservation_id="child",
                run_id="run-late",
                model_invocation_ids=["late-provider-receipt"],
                provider_requests=1,
                input_tokens=3,
                output_tokens=2,
                cost_units=0.1,
            )
        )

        assert _status(store, "child") == ReservationStatus.RECONCILED.value
        assert store.unsettled_reservation_ids("run-late") == []
    finally:
        store.close()


@pytest.mark.asyncio
async def test_paid_response_survives_accounting_failure_and_reports_actual_cost() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "ok"})}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 10},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    store = _FailingSettlementStore()
    gateway = QwenGateway(_settings(), client, usage_store=store)  # type: ignore[arg-type]
    try:
        output, meta = await gateway.structured(
            role="planner",
            system_prompt="Return a bounded answer.",
            user_prompt="answer",
            output_model=_Answer,
            prompt_version="test-v07",
            run_id="run-paid",
        )
    finally:
        await client.aclose()

    assert output.answer == "ok"
    assert meta.usage.provider_requests == 1
    assert meta.usage.input_tokens == 30
    assert meta.usage.output_tokens == 10
    assert meta.usage.cost_units > 0
    attempt = gateway.provider_attempts[-1]
    assert attempt.succeeded is True
    assert attempt.usage == meta.usage
    assert store.settlements[0].cost_units == meta.usage.cost_units


@pytest.mark.asyncio
async def test_accounting_failure_does_not_replace_transport_timeout() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("provider read timed out", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(
        _settings(),
        client,
        usage_store=_FailingSettlementStore(),  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(httpx.ReadTimeout, match="provider read timed out"):
            await gateway._request_with_retry(  # noqa: SLF001 - fault-injection contract test
                "qwen-plus",
                "system",
                "user",
                _Answer.model_json_schema(),
                run_id="run-timeout",
                prompt_version="test-prompt-v1",
            )
    finally:
        await client.aclose()

    attempt = gateway.provider_attempts[-1]
    assert attempt.succeeded is False
    assert attempt.retryable is True
    assert attempt.error_type == "timeout"
    assert attempt.usage.provider_requests == 1


@pytest.mark.asyncio
async def test_concurrent_acknowledgement_cannot_shift_model_call_usage_boundary() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        entered.set()
        await release.wait()
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": "new"})}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(_settings(), client)
    gateway._record_attempt(  # noqa: SLF001 - establish an older pending attempt
        "qwen-plus",
        "chat",
        time.monotonic(),
        200,
        True,
        False,
        None,
        {"prompt_tokens": 3, "completion_tokens": 2},
        run_id="run-old",
        provider_request_sha256="b" * 64,
        prompt_version="test-prompt-v1",
        response_sha256="c" * 64,
    )
    old_sequence = gateway.provider_attempts[0].sequence

    task = asyncio.create_task(
        gateway.structured(
            role="planner",
            system_prompt="Return a bounded answer.",
            user_prompt="answer",
            output_model=_Answer,
            prompt_version="test-v07",
            run_id="run-new",
        )
    )
    await entered.wait()
    # This removal shifts list index 1 to index 0. A list-offset accounting
    # boundary would consequently lose the in-flight run-new attempt.
    gateway.acknowledge_provider_attempts("run-old", {old_sequence})
    release.set()
    try:
        output, meta = await task
    finally:
        await client.aclose()

    assert output.answer == "new"
    assert meta.usage.provider_requests == 1
    assert meta.usage.input_tokens == 11
    assert meta.usage.output_tokens == 7
    assert meta.usage.cost_units > 0


@pytest.mark.asyncio
async def test_same_run_concurrent_calls_account_only_their_own_provider_attempt() -> None:
    slow_entered = asyncio.Event()
    release_slow = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        user_prompt = payload["messages"][-1]["content"]
        if user_prompt == "slow-call":
            slow_entered.set()
            await release_slow.wait()
            answer = "slow"
            usage = {"prompt_tokens": 13, "completion_tokens": 2}
        else:
            assert user_prompt == "fast-call"
            answer = "fast"
            usage = {"prompt_tokens": 41, "completion_tokens": 5}
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"answer": answer})}}],
                "usage": usage,
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gateway = QwenGateway(_settings(), client)
    slow_task = asyncio.create_task(
        gateway.structured(
            role="planner",
            system_prompt="Return a bounded answer.",
            user_prompt="slow-call",
            output_model=_Answer,
            prompt_version="test-v07",
            run_id="run-shared",
        )
    )
    fast_task: asyncio.Task[tuple[_Answer, Any]] | None = None
    try:
        await slow_entered.wait()
        fast_task = asyncio.create_task(
            gateway.structured(
                role="planner",
                system_prompt="Return a bounded answer.",
                user_prompt="fast-call",
                output_model=_Answer,
                prompt_version="test-v07",
                run_id="run-shared",
            )
        )
        fast_output, fast_meta = await fast_task
        release_slow.set()
        slow_output, slow_meta = await slow_task
    finally:
        release_slow.set()
        pending = [task for task in (slow_task, fast_task) if task is not None and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await client.aclose()

    assert fast_output.answer == "fast"
    assert fast_meta.usage.provider_requests == 1
    assert fast_meta.usage.input_tokens == 41
    assert fast_meta.usage.output_tokens == 5
    assert slow_output.answer == "slow"
    assert slow_meta.usage.provider_requests == 1
    assert slow_meta.usage.input_tokens == 13
    assert slow_meta.usage.output_tokens == 2

    attempts = gateway.provider_attempts_for("run-shared")
    assert len(attempts) == 2
    assert len({attempt.logical_call_id for attempt in attempts}) == 2
