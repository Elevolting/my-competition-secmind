from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from secmind.ledger import canonical_json, redact
from secmind.schemas import HookDecision, HookEvent, HookResult

HookHandler = Callable[[HookEvent], HookResult | Awaitable[HookResult]]

PROTECTED_PATCH_KEYS = {
    "approval",
    "fence",
    "grant",
    "manifest",
    "network_policy",
    "policy",
    "runner_policy",
    "scope",
}


class HookRegistrationError(ValueError):
    pass


class HookExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class HookRegistration:
    hook_id: str
    version: str
    events: frozenset[str]
    handler: HookHandler
    signature_verified: bool
    deterministic: bool = True
    advisory_only: bool = False
    security_critical: bool = False
    timeout_seconds: float = 2.0
    fail_closed: bool = True


class HookBus:
    """Managed deterministic lifecycle hooks that cannot replace PDP or Broker."""

    def __init__(self) -> None:
        self._hooks: dict[str, HookRegistration] = {}
        self._cache: dict[tuple[str, str, str], HookResult] = {}

    def register(self, registration: HookRegistration) -> None:
        if registration.hook_id in self._hooks:
            raise HookRegistrationError(f"duplicate hook id: {registration.hook_id}")
        if not registration.signature_verified:
            raise HookRegistrationError("hook is not signed by a trusted platform key")
        if registration.security_critical and (registration.advisory_only or not registration.deterministic):
            raise HookRegistrationError("security hooks must be deterministic platform code")
        if registration.timeout_seconds <= 0:
            raise HookRegistrationError("hook timeout must be positive")
        self._hooks[registration.hook_id] = registration

    async def dispatch(self, event: HookEvent) -> list[HookResult]:
        results: list[HookResult] = []
        for registration in sorted(self._hooks.values(), key=lambda item: item.hook_id):
            if event.event_type not in registration.events:
                continue
            key = (event.event_id, registration.hook_id, registration.version)
            cached = self._cache.get(key)
            if cached is not None:
                results.append(cached)
                continue
            result = await self._execute(registration, event)
            self._validate_result(registration, result)
            result = result.model_copy(
                update={
                    "event_id": str(
                        uuid5(
                            NAMESPACE_URL,
                            f"secmind:hook-result:{event.event_id}:{registration.hook_id}:{registration.version}",
                        )
                    )
                }
            )
            self._cache[key] = result
            results.append(result)
        return results

    async def _execute(self, registration: HookRegistration, event: HookEvent) -> HookResult:
        started = time.monotonic()
        stable_event = event.model_dump(mode="json", exclude={"created_at"})
        input_hash = hashlib.sha256(canonical_json(redact(stable_event)).encode()).hexdigest()
        try:
            produced = registration.handler(event)
            if inspect.isawaitable(produced):
                result = await asyncio.wait_for(produced, timeout=registration.timeout_seconds)
            else:
                result = produced
        except Exception as exc:
            if registration.security_critical or registration.fail_closed:
                decision = HookDecision.DENY
            else:
                decision = HookDecision.ADVISORY
            payload = {
                "hook_id": registration.hook_id,
                "event_id": event.event_id,
                "decision": decision.value,
                "error_type": type(exc).__name__,
            }
            output_hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
            return HookResult(
                hook_id=registration.hook_id,
                event_id=event.event_id,
                decision=decision,
                error=f"{type(exc).__name__}: hook execution failed",
                duration_ms=int((time.monotonic() - started) * 1000),
                input_hash=input_hash,
                output_hash=output_hash,
            )
        safe = redact(result.model_dump(mode="json"))
        output_hash = hashlib.sha256(canonical_json(safe).encode()).hexdigest()
        return result.model_copy(
            update={
                "duration_ms": int((time.monotonic() - started) * 1000),
                "input_hash": input_hash,
                "output_hash": output_hash,
            }
        )

    @staticmethod
    def _validate_result(registration: HookRegistration, result: HookResult) -> None:
        if result.hook_id != registration.hook_id:
            raise HookExecutionError("hook result identity mismatch")
        if registration.advisory_only and result.decision not in {
            HookDecision.ADVISORY,
            HookDecision.CONTINUE,
        }:
            raise HookExecutionError("advisory hook attempted to make an authorization decision")
        protected = PROTECTED_PATCH_KEYS & {str(key).lower() for key in result.patch}
        if protected:
            raise HookExecutionError(f"hook attempted to patch protected fields: {sorted(protected)}")
