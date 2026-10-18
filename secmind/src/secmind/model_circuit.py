"""Scoped model-provider circuit breaker with a single half-open probe."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite


class CircuitPermit(StrEnum):
    CLOSED = "closed"
    HALF_OPEN_PROBE = "half_open_probe"
    OPEN = "open"


@dataclass
class _CircuitState:
    consecutive_failures: int = 0
    open_until: float = 0.0
    probe_active: bool = False


class ScopedCircuitBreaker:
    """Trip only on provider/transport faults, never task-local content errors.

    Callers choose the scope key. SecMind uses a provider/model key so
    infrastructure faults are shared across payload profiles while schema,
    parse, content, and budget faults remain task-local. After the cooldown
    exactly one caller receives a half-open probe permit; concurrent callers
    remain fail-fast until that probe settles.
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1 or cooldown_seconds <= 0:
            raise ValueError("circuit breaker bounds must be positive")
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._states: dict[str, _CircuitState] = {}
        self._lock = threading.Lock()

    def acquire(self, scope: str) -> CircuitPermit:
        now = self._clock()
        with self._lock:
            state = self._states.setdefault(scope, _CircuitState())
            if state.open_until > now:
                return CircuitPermit.OPEN
            if state.consecutive_failures < self.failure_threshold:
                return CircuitPermit.CLOSED
            if state.probe_active:
                return CircuitPermit.OPEN
            state.probe_active = True
            return CircuitPermit.HALF_OPEN_PROBE

    def record_success(self, scope: str) -> None:
        with self._lock:
            self._states.pop(scope, None)

    def record_failure(
        self,
        scope: str,
        *,
        provider_scoped: bool,
        cooldown_seconds: float | None = None,
    ) -> None:
        """Settle one permit without letting task-local faults erase provider state.

        Schema, parse, content and budget failures prove the provider route is
        reachable. They must not poison another run that happens to share it.
        A task-local failure from the single half-open probe does release that
        probe and returns the provider scope to closed; an active provider
        cooldown or accumulated provider failures are otherwise preserved.
        """

        now = self._clock()
        with self._lock:
            if not provider_scoped:
                state = self._states.get(scope)
                if state is not None and state.open_until <= now and state.probe_active:
                    self._states.pop(scope, None)
                return
            state = self._states.setdefault(scope, _CircuitState())
            state.consecutive_failures += 1
            state.probe_active = False
            explicit_cooldown = (
                min(300.0, max(0.0, cooldown_seconds))
                if cooldown_seconds is not None and isfinite(cooldown_seconds)
                else 0.0
            )
            if explicit_cooldown > 0:
                # A provider-supplied Retry-After is authoritative for this
                # bounded route even before the generic failure threshold.
                state.open_until = max(state.open_until, now + explicit_cooldown)
            elif state.consecutive_failures >= self.failure_threshold:
                state.open_until = max(state.open_until, now + self.cooldown_seconds)

    def snapshot(self, scope: str) -> dict[str, int | float | bool]:
        with self._lock:
            state = self._states.get(scope, _CircuitState())
            return {
                "consecutive_failures": state.consecutive_failures,
                "open_until": state.open_until,
                "probe_active": state.probe_active,
            }


__all__ = ["CircuitPermit", "ScopedCircuitBreaker"]
