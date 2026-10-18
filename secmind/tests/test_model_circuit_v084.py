from __future__ import annotations

from secmind.llm import QwenGateway
from secmind.model_circuit import CircuitPermit, ScopedCircuitBreaker
from secmind.model_router import FALLBACK_ROUTE_PROFILE, PRIMARY_ROUTE_PROFILE


def test_circuit_allows_exactly_one_half_open_probe() -> None:
    now = [100.0]
    breaker = ScopedCircuitBreaker(failure_threshold=2, cooldown_seconds=10, clock=lambda: now[0])
    scope = "deepseek:deepseek-v4-flash:primary"

    assert breaker.acquire(scope) is CircuitPermit.CLOSED
    breaker.record_failure(scope, provider_scoped=True)
    assert breaker.acquire(scope) is CircuitPermit.CLOSED
    breaker.record_failure(scope, provider_scoped=True)
    assert breaker.acquire(scope) is CircuitPermit.OPEN

    now[0] = 111.0
    assert breaker.acquire(scope) is CircuitPermit.HALF_OPEN_PROBE
    assert breaker.acquire(scope) is CircuitPermit.OPEN
    breaker.record_success(scope)
    assert breaker.acquire(scope) is CircuitPermit.CLOSED


def test_task_local_failure_never_poison_provider_scope() -> None:
    breaker = ScopedCircuitBreaker(failure_threshold=1, cooldown_seconds=10)
    scope = "provider:model:route"

    assert breaker.acquire(scope) is CircuitPermit.CLOSED
    breaker.record_failure(scope, provider_scoped=False)
    assert breaker.acquire(scope) is CircuitPermit.CLOSED
    assert breaker.snapshot(scope)["consecutive_failures"] == 0


def test_provider_retry_after_opens_circuit_before_generic_threshold() -> None:
    now = [100.0]
    breaker = ScopedCircuitBreaker(failure_threshold=5, cooldown_seconds=60, clock=lambda: now[0])
    scope = "deepseek:deepseek-v4-flash"

    breaker.record_failure(scope, provider_scoped=True, cooldown_seconds=7.0)
    assert breaker.acquire(scope) is CircuitPermit.OPEN
    assert breaker.snapshot(scope)["open_until"] == 107.0
    now[0] = 108.0
    assert breaker.acquire(scope) is CircuitPermit.CLOSED


def test_failed_half_open_probe_reopens_for_full_cooldown() -> None:
    now = [0.0]
    breaker = ScopedCircuitBreaker(failure_threshold=1, cooldown_seconds=5, clock=lambda: now[0])
    scope = "provider:model:route"
    breaker.record_failure(scope, provider_scoped=True)
    now[0] = 6.0
    assert breaker.acquire(scope) is CircuitPermit.HALF_OPEN_PROBE
    breaker.record_failure(scope, provider_scoped=True)
    assert breaker.acquire(scope) is CircuitPermit.OPEN
    assert breaker.snapshot(scope)["open_until"] == 11.0


def test_shared_provider_model_scope_allows_one_cross_profile_probe() -> None:
    now = [0.0]
    breaker = ScopedCircuitBreaker(failure_threshold=1, cooldown_seconds=5, clock=lambda: now[0])
    primary_scope = QwenGateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001
    fallback_scope = QwenGateway._route_key("qwen-plus", FALLBACK_ROUTE_PROFILE)  # noqa: SLF001

    assert primary_scope == fallback_scope
    breaker.record_failure(primary_scope, provider_scoped=True)
    assert breaker.acquire(fallback_scope) is CircuitPermit.OPEN

    now[0] = 6.0
    assert breaker.acquire(primary_scope) is CircuitPermit.HALF_OPEN_PROBE
    assert breaker.acquire(fallback_scope) is CircuitPermit.OPEN
    breaker.record_success(primary_scope)
    assert breaker.acquire(fallback_scope) is CircuitPermit.CLOSED


def test_task_local_failure_preserves_provider_failures_without_opening_scope() -> None:
    breaker = ScopedCircuitBreaker(failure_threshold=2, cooldown_seconds=10)
    scope = QwenGateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001

    breaker.record_failure(scope, provider_scoped=True)
    breaker.record_failure(scope, provider_scoped=False)

    assert breaker.snapshot(scope)["consecutive_failures"] == 1
    assert breaker.acquire(scope) is CircuitPermit.CLOSED


def test_task_local_half_open_failure_releases_only_the_probe() -> None:
    now = [0.0]
    breaker = ScopedCircuitBreaker(failure_threshold=1, cooldown_seconds=5, clock=lambda: now[0])
    scope = QwenGateway._route_key("qwen-plus", PRIMARY_ROUTE_PROFILE)  # noqa: SLF001

    breaker.record_failure(scope, provider_scoped=True)
    now[0] = 6.0
    assert breaker.acquire(scope) is CircuitPermit.HALF_OPEN_PROBE
    breaker.record_failure(scope, provider_scoped=False)
    assert breaker.acquire(scope) is CircuitPermit.CLOSED
