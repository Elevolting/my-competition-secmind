from __future__ import annotations

import asyncio

import pytest

from secmind.hook_bus import HookBus, HookExecutionError, HookRegistration, HookRegistrationError
from secmind.schemas import HookDecision, HookEvent, HookResult


def _result(event: HookEvent, *, decision: HookDecision, patch=None) -> HookResult:
    return HookResult(
        hook_id="hook",
        event_id=event.event_id,
        decision=decision,
        patch=patch or {},
        input_hash="0" * 64,
        output_hash="0" * 64,
    )


@pytest.mark.asyncio
async def test_signed_hook_is_idempotent_by_event_and_version() -> None:
    calls = 0

    def handler(event: HookEvent) -> HookResult:
        nonlocal calls
        calls += 1
        return _result(event, decision=HookDecision.CONTINUE)

    bus = HookBus()
    bus.register(
        HookRegistration(
            hook_id="hook",
            version="1",
            events=frozenset({"PreTool"}),
            handler=handler,
            signature_verified=True,
        )
    )
    event = HookEvent(run_id="run", event_type="PreTool")
    first = await bus.dispatch(event)
    second = await bus.dispatch(event)
    assert first == second
    assert calls == 1


@pytest.mark.asyncio
async def test_security_hook_timeout_fails_closed() -> None:
    async def handler(event: HookEvent) -> HookResult:
        await asyncio.sleep(0.05)
        return _result(event, decision=HookDecision.CONTINUE)

    bus = HookBus()
    bus.register(
        HookRegistration(
            hook_id="hook",
            version="1",
            events=frozenset({"PreTool"}),
            handler=handler,
            signature_verified=True,
            security_critical=True,
            timeout_seconds=0.001,
        )
    )
    [result] = await bus.dispatch(HookEvent(run_id="run", event_type="PreTool"))
    assert result.decision == HookDecision.DENY
    assert result.error is not None


@pytest.mark.asyncio
async def test_advisory_hook_cannot_authorize_or_patch_security_boundary() -> None:
    bus = HookBus()
    bus.register(
        HookRegistration(
            hook_id="hook",
            version="1",
            events=frozenset({"PreTool"}),
            handler=lambda event: _result(event, decision=HookDecision.PATCH, patch={"scope": ["*"]}),
            signature_verified=True,
            advisory_only=True,
        )
    )
    with pytest.raises(HookExecutionError):
        await bus.dispatch(HookEvent(run_id="run", event_type="PreTool"))


def test_unsigned_security_hook_is_rejected() -> None:
    bus = HookBus()
    with pytest.raises(HookRegistrationError):
        bus.register(
            HookRegistration(
                hook_id="hook",
                version="1",
                events=frozenset({"PreTool"}),
                handler=lambda event: _result(event, decision=HookDecision.CONTINUE),
                signature_verified=False,
                security_critical=True,
            )
        )
