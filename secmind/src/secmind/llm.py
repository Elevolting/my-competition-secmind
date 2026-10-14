from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NoReturn, TypeVar
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
from pydantic import BaseModel, ValidationError

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.config import Settings
from secmind.investigation.contracts import (
    UsageReservation,
    seal_contract,
)
from secmind.investigation.store import InvestigationStore
from secmind.model_circuit import CircuitPermit, ScopedCircuitBreaker
from secmind.model_gateway.budget import (
    bounded_usage_count,
    cost_units,
    estimate_prompt_tokens,
    merge_usage,
)
from secmind.model_gateway.contracts import (
    DurableReceiptError,
    ModelAttemptSummary,
    ModelCallMeta,
    ModelGatewayError,
    ModelGatewayFailure,
    ModelReadIdleTimeout,
    ModelResponseTooLargeError,
    ProviderAttempt,
    RawModelResponseReceipt,
    RetryableModelError,
)
from secmind.model_gateway.diagnostics import (
    build_failure,
    failure_category,
    record_attempt,
    schema_failure_summary,
    summaries_for_call,
)
from secmind.model_gateway.embeddings import embeddings as run_embeddings
from secmind.model_gateway.identity import (
    canonical_sha256,
    legacy_selection_digest,
    lineage_stage,
    raw_response_slot_id,
    recovery_independence,
    recovery_kind,
)
from secmind.model_gateway.json_recovery import extract_first_json_value, parse_model
from secmind.model_gateway.receipts import (
    RAW_RESPONSE_MEDIA_TYPE,
    RAW_RESPONSE_OBJECT_TYPE,
    load_raw_response_receipt,
    persist_raw_response_receipt,
    read_raw_response,
)
from secmind.model_gateway.recovery_policy import (
    fallback_eligibility,
    fallback_wait_decision,
    infrastructure_fallback_prompt,
    latest_retry_after_seconds,
    schema_fallback_prompt,
)
from secmind.model_gateway.transport import read_bounded_response, request_with_retry
from secmind.model_gateway.usage_provenance import UsageProvenance
from secmind.model_policy import MODEL_CATALOG, ModelMode, ModelPolicy, ModelPolicyError
from secmind.model_router import (
    FALLBACK_ROUTE_PROFILE,
    MODEL_ROUTER_VERSION,
    PRIMARY_ROUTE_PROFILE,
    ModelRouteDecision,
    ModelRouter,
    ModelTaskKind,
)
from secmind.model_snapshots import ModelConfiguration, ModelSnapshotStore, SnapshotParent
from secmind.schemas import ModelUsage

if TYPE_CHECKING:
    from secmind.prompting.contracts import PromptArtifact

T = TypeVar("T", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class _StructuredCallSetup:
    """Immutable identities and deadlines prepared before provider execution."""

    system_prompt: str
    user_prompt: str
    prompt_version: str
    prompt_artifact_id: str | None
    prompt_selection_digest: str
    prompt_optimizer_attempt_id: str | None
    prompt_lineage_reason: str
    parent_logical_call_id: str
    route: ModelRouteDecision
    strict_primary: bool
    bounded_single_attempt: bool
    candidate_specs: tuple[tuple[str, str, bool], ...]
    logical_started_at: float
    task_deadline_at: float
    primary_header_deadline_at: float
    primary_stream_deadline_at: float
    deadline_at: float
    stream_deadline_at: float
    deadline_ms: int
    response_schema: dict[str, Any]
    response_schema_sha256: str
    request_sha256: str
    logical_call_id: str
    attempt_sequence_floor: int
    full_task_budget_ms: int


logger = logging.getLogger(__name__)

_canonical_sha256 = canonical_sha256
_legacy_selection_digest = legacy_selection_digest
_lineage_stage = lineage_stage
_recovery_kind = recovery_kind
_recovery_independence = recovery_independence
_merge_usage = merge_usage
_bounded_usage_count = bounded_usage_count
_extract_first_json_value = extract_first_json_value
_read_bounded_response = read_bounded_response
_raw_response_slot_id = raw_response_slot_id
_RAW_RESPONSE_OBJECT_TYPE = RAW_RESPONSE_OBJECT_TYPE
_RAW_RESPONSE_MEDIA_TYPE = RAW_RESPONSE_MEDIA_TYPE

__all__ = [
    "DurableReceiptError",
    "ModelAttemptSummary",
    "ModelCallMeta",
    "ModelGatewayError",
    "ModelGatewayFailure",
    "ModelReadIdleTimeout",
    "ModelResponseTooLargeError",
    "ProviderAttempt",
    "QwenGateway",
    "RawModelResponseReceipt",
    "RetryableModelError",
    "close_gateway_safely",
    "estimate_prompt_tokens",
]


class QwenGateway:
    """OpenAI-compatible Qwen gateway with retry, circuit breaking, and fallback."""

    def __init__(
        self,
        settings: Settings,
        client: httpx.AsyncClient | None = None,
        *,
        usage_store: InvestigationStore | None = None,
        artifact_store: ContentAddressedArtifactStore | None = None,
        attempt_sink: Callable[[str, list[ProviderAttempt]], None] | None = None,
        snapshot_store: ModelSnapshotStore | None = None,
    ) -> None:
        self.settings = settings
        self.snapshot_store = snapshot_store
        try:
            self.policy = ModelPolicy.from_settings(settings, injected_client=client is not None)
        except ModelPolicyError as exc:
            raise ModelGatewayError(str(exc)) from exc
        self.router = ModelRouter(self.policy)
        self._client = client
        self._owns_client = False
        if self.policy.mode is ModelMode.MOCK and (
            self._client is None or not isinstance(self._client._transport, httpx.MockTransport)  # noqa: SLF001
        ):
            raise ModelGatewayError("mock mode requires httpx.MockTransport; network transports are forbidden")
        if self.policy.mode is ModelMode.LIVE and self._client is None:
            self._client = httpx.AsyncClient(timeout=self._http_timeout())
            self._owns_client = True
        self._circuit = ScopedCircuitBreaker(failure_threshold=3, cooldown_seconds=60)
        self._provider_attempts: list[ProviderAttempt] = []
        # Keep request identities monotonic even after the coordinator drains the
        # in-memory batch.  Reusing sequence 1 would make a later provider request
        # collide with an earlier durable model_invocations record.
        self._provider_sequence = 0
        self._usage_store = usage_store
        self._attempt_sink = attempt_sink
        self._artifact_store = (
            artifact_store
            if artifact_store is not None
            else ContentAddressedArtifactStore(settings.artifact_root)
            if usage_store is not None
            else None
        )

    def snapshot_configuration(self, model_id: str) -> ModelConfiguration:
        return ModelConfiguration(
            base_url=self.policy.base_url, provider=self.policy.chat_provider, model_id=model_id,
            planner_model=self.policy.planner.model_id, worker_model=self.policy.worker.model_id,
            fallback_model=self.policy.fallback.model_id,
        )

    async def answer_side_question(
        self, snapshot: dict[str, Any], question: str,
    ) -> tuple[str, dict[str, int]]:
        """Ask a bounded question using the frozen request context."""

        if self.policy.mode is not ModelMode.LIVE:
            raise ModelGatewayError("side-question model calls require live model mode")
        request = copy.deepcopy(snapshot.get("request"))
        if not isinstance(request, dict) or not isinstance(request.get("messages"), list):
            raise ModelGatewayError("side-question snapshot has no usable messages")
        messages = request["messages"]
        messages.append({"role": "user", "content": question})
        payload: dict[str, Any] = {
            "model": str(snapshot["model_id"]),
            "messages": messages,
            "max_tokens": self.settings.side_question_output_token_budget,
            "temperature": 0,
        }
        response = await self._require_provider().post(
            f"{self.policy.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key()}"},
            json=payload,
            timeout=self.settings.model_timeout_seconds,
        )
        if response.status_code >= 400:
            raise ModelGatewayError(f"Model response: {response.status_code}")
        try:
            body = json.loads((await read_bounded_response(
                response, max_bytes=self.settings.model_max_response_bytes,
                read_idle_timeout_seconds=self.settings.model_read_idle_timeout_seconds,
            )).decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            usage = body.get("usage") or {}
            normalized = {
                "input_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
                "output_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
            }
            if not isinstance(content, str) or not content.strip():
                raise ValueError("empty model content")
            return content, normalized
        except (UnicodeDecodeError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise ModelGatewayError("Malformed side-question model response") from exc

    async def _capture_request(self, payload: dict, parent: SnapshotParent | None, provenance: dict) -> None:
        if self.snapshot_store is None or parent is None:
            return
        try:
            await asyncio.to_thread(
                self.snapshot_store.capture, parent=parent,
                configuration=self.snapshot_configuration(payload["model"]), request=payload, provenance=provenance,
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("Model snapshot capture failed (%s)", type(exc).__name__)

    def _http_timeout(self) -> httpx.Timeout:
        """Build phase timeouts; the logical call deadline lives above HTTPX."""

        return httpx.Timeout(
            timeout=None,
            connect=self.settings.model_connect_timeout_seconds,
            pool=self.settings.model_pool_timeout_seconds,
            write=self.settings.model_write_timeout_seconds,
            read=self.settings.model_read_idle_timeout_seconds,
        )

    def _api_key(self) -> str:
        return self.settings.model_api_key_value(self.policy.chat_provider)

    @staticmethod
    def _route_key(model_id: str, route_profile: str | None = None) -> str:
        """Return the provider/model circuit scope, independent of payload profile."""

        del route_profile
        entry = MODEL_CATALOG.get(model_id)
        provider = "unknown" if entry is None else entry.provider
        return f"{provider}:{model_id}"

    @staticmethod
    def _route_name(task_kind: str, lane: str) -> str:
        return f"{task_kind}:{lane}"

    @staticmethod
    def _timeout_stage(exc: BaseException) -> str:
        name = type(exc).__name__.casefold()
        if "connect" in name:
            return "connect"
        if "pool" in name:
            return "pool"
        if "write" in name:
            return "write"
        if "read" in name:
            return "read_idle"
        return "transport"

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    @property
    def provider_attempts(self) -> tuple[ProviderAttempt, ...]:
        """Immutable attempt log for later persistence by the coordinator."""
        return tuple(self._provider_attempts)

    def drain_provider_attempts(self) -> tuple[ProviderAttempt, ...]:
        attempts = tuple(self._provider_attempts)
        self._provider_attempts.clear()
        return attempts

    def provider_attempts_for(self, run_id: str) -> tuple[ProviderAttempt, ...]:
        return tuple(item for item in self._provider_attempts if item.run_id == run_id)

    def acknowledge_provider_attempts(self, run_id: str, sequences: set[int]) -> None:
        self._provider_attempts = [
            item for item in self._provider_attempts if item.run_id != run_id or item.sequence not in sequences
        ]

    def _require_provider(self) -> httpx.AsyncClient:
        if not self.policy.network_enabled:
            raise ModelGatewayError("Model calls are disabled in offline mode")
        if self._client is None:  # Defensive: mock mode is rejected at construction without one.
            raise ModelGatewayError("No provider client is configured")
        return self._client

    def _summaries_for_call(
        self,
        logical_call_id: str,
        *,
        extra: list[ModelAttemptSummary] | None = None,
    ) -> list[ModelAttemptSummary]:
        return summaries_for_call(self._provider_attempts, logical_call_id, extra=extra)

    @staticmethod
    def _failure_category(summary: ModelAttemptSummary | None, last_error: BaseException | None) -> str:
        return failure_category(summary, last_error)

    def _build_failure(
        self,
        *,
        logical_call_id: str,
        last_error: BaseException | None,
        route: str,
        route_profile: str,
        model_id: str,
        prompt_version: str,
        deadline_ms: int,
        deadline_at: float,
        fallback_status: str,
        recovery_kind: str = "primary",
        recovery_independence: str = "not_applicable",
        extra_attempts: list[ModelAttemptSummary] | None = None,
    ) -> ModelGatewayFailure:
        return build_failure(
            self._provider_attempts,
            logical_call_id=logical_call_id,
            last_error=last_error,
            route=route,
            route_profile=route_profile,
            model_id=model_id,
            prompt_version=prompt_version,
            deadline_ms=deadline_ms,
            deadline_at=deadline_at,
            fallback_status=fallback_status,
            recovery_kind=recovery_kind,
            recovery_independence=recovery_independence,
            extra_attempts=extra_attempts,
        )

    @staticmethod
    def _schema_failure_summary(
        attempts: list[ModelAttemptSummary],
        *,
        route: str,
        route_profile: str,
        model_id: str,
        prompt_version: str,
        deadline_ms: int,
        remaining_budget_ms: int,
        logical_call_id: str,
        parent_logical_call_id: str | None,
        prompt_optimizer_attempt_id: str | None,
        prompt_lineage_reason: str,
        lineage_stage: str,
        recovery_kind: str,
        recovery_independence: str,
    ) -> ModelAttemptSummary:
        return schema_failure_summary(
            attempts,
            route=route,
            route_profile=route_profile,
            model_id=model_id,
            prompt_version=prompt_version,
            deadline_ms=deadline_ms,
            remaining_budget_ms=remaining_budget_ms,
            logical_call_id=logical_call_id,
            parent_logical_call_id=parent_logical_call_id,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            lineage_stage=lineage_stage,
            recovery_kind=recovery_kind,
            recovery_independence=recovery_independence,
        )

    def _prepare_structured_call(
        self,
        *,
        role: str,
        system_prompt: str,
        user_prompt: str,
        output_model: type[BaseModel],
        prompt_version: str,
        run_id: str | None,
        prompt_artifact: PromptArtifact | None,
        durable_call_key: str | None,
        task_kind: ModelTaskKind | str | None,
        prompt_selection_digest: str | None,
        prompt_optimizer_attempt_id: str | None,
        prompt_lineage_reason: str | None,
        parent_logical_call_id: str | None,
    ) -> _StructuredCallSetup:
        """Resolve immutable prompt identity, route, and deadline state."""

        if self.settings.demo_mode:
            raise ModelGatewayError("Model calls are disabled in deterministic demo mode")
        if prompt_artifact is not None:
            if run_id is not None and prompt_artifact.run_id != run_id:
                raise ModelGatewayError("prompt artifact belongs to another run")
            system_prompt = prompt_artifact.system_prompt
            user_prompt = prompt_artifact.compose_user_prompt(user_prompt)
            prompt_version = prompt_artifact.prompt_version
            prompt_selection_digest = prompt_artifact.selection_digest
            prompt_optimizer_attempt_id = prompt_artifact.optimizer_attempt_id
            prompt_lineage_reason = prompt_artifact.lineage_reason
        else:
            prompt_selection_digest = prompt_selection_digest or _legacy_selection_digest(
                prompt_version=prompt_version,
                role=role,
                task_kind=ModelTaskKind(task_kind).value if task_kind is not None else "legacy",
            )
            prompt_lineage_reason = prompt_lineage_reason or "legacy_unbound_prompt"
        self._require_provider()
        route = self.router.route(task_kind, role=role)
        logger.info(
            "model_route_selected",
            extra={
                "run_id": run_id,
                "role": role,
                "task_kind": route.task_kind.value,
                "lane": route.lane.value,
                "router_version": route.router_version,
                "primary_model": route.primary.model_id,
                "fallback_model": route.fallback.model_id,
            },
        )
        strict_primary = route.task_kind is ModelTaskKind.PRIMARY_REVIEW
        bounded_single_attempt = strict_primary or route.task_kind in {
            ModelTaskKind.CRITIC_REVIEW,
            ModelTaskKind.PROMPT_OPTIMIZATION,
            ModelTaskKind.CLASSIFICATION,
            ModelTaskKind.SUMMARIZATION,
            ModelTaskKind.EXTRACTION,
        }
        if strict_primary:
            candidate_specs = [(route.primary.model_id, route.primary_profile, False)]
            if self.settings.model_primary_fallback_enabled:
                candidate_specs.append((route.fallback.model_id, route.fallback_profile, True))
        else:
            candidates = list(dict.fromkeys([route.primary.model_id, route.fallback.model_id]))
            candidate_specs = [
                (
                    model_id,
                    route.primary_profile if index == 0 else route.fallback_profile,
                    index > 0,
                )
                for index, model_id in enumerate(candidates)
            ]
        logical_started_at = time.monotonic()
        if strict_primary:
            task_deadline_at = logical_started_at + self.settings.model_task_hard_timeout_seconds
            primary_header_deadline_at = logical_started_at + self.settings.model_primary_soft_timeout_seconds
            primary_stream_deadline_at = min(
                task_deadline_at - self.settings.model_recovery_reserve_seconds,
                logical_started_at
                + self.settings.model_primary_soft_timeout_seconds
                + self.settings.model_stream_max_seconds,
            )
            deadline_at = primary_header_deadline_at
            stream_deadline_at = primary_stream_deadline_at
        else:
            task_deadline_at = logical_started_at + self.settings.model_timeout_seconds
            primary_header_deadline_at = task_deadline_at
            primary_stream_deadline_at = task_deadline_at
            deadline_at = task_deadline_at
            stream_deadline_at = task_deadline_at
        deadline_ms = max(0, int((deadline_at - logical_started_at) * 1000))
        response_schema = output_model.model_json_schema()
        response_schema_sha256 = hashlib.sha256(
            json.dumps(response_schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        request_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "role": role,
                    "route_task_kind": route.task_kind.value,
                    "route_lane": route.lane.value,
                    "router_version": route.router_version,
                    "system_prompt": system_prompt,
                    "user_prompt": user_prompt,
                    "prompt_version": prompt_version,
                    # Keep the historical null slot so byte-equivalent fixed
                    # artifacts retain the request identity used by v0.7.1.
                    "prompt_artifact_id": None,
                    "response_schema_sha256": response_schema_sha256,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if durable_call_key is not None and run_id is None:
            raise ModelGatewayError("durable model calls require a run_id")
        logical_call_id = (
            str(uuid5(NAMESPACE_URL, f"secmind:model-call:{run_id}:{durable_call_key}:{request_sha256}"))
            if durable_call_key is not None
            else str(uuid4())
        )
        parent_logical_call_id = parent_logical_call_id or logical_call_id
        return _StructuredCallSetup(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            prompt_version=prompt_version,
            prompt_artifact_id=None if prompt_artifact is None else prompt_artifact.artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            route=route,
            strict_primary=strict_primary,
            bounded_single_attempt=bounded_single_attempt,
            candidate_specs=tuple(candidate_specs),
            logical_started_at=logical_started_at,
            task_deadline_at=task_deadline_at,
            primary_header_deadline_at=primary_header_deadline_at,
            primary_stream_deadline_at=primary_stream_deadline_at,
            deadline_at=deadline_at,
            stream_deadline_at=stream_deadline_at,
            deadline_ms=deadline_ms,
            response_schema=response_schema,
            response_schema_sha256=response_schema_sha256,
            request_sha256=request_sha256,
            logical_call_id=logical_call_id,
            attempt_sequence_floor=self._provider_sequence,
            full_task_budget_ms=max(0, int((task_deadline_at - logical_started_at) * 1000)),
        )

    def _raise_structured_failure(
        self,
        *,
        setup: _StructuredCallSetup,
        fallback_attempted: bool,
        fallback_status: str,
        fallback_block_reason: str,
        diagnostic_extra: list[ModelAttemptSummary],
        last_error: BaseException | None,
        deadline_at: float,
        deadline_ms: int,
    ) -> NoReturn:
        """Build the stable public failure after every bounded slot is exhausted."""

        if setup.strict_primary and fallback_attempted and fallback_status == "attempted":
            fallback_status = "failed"
        summaries = self._summaries_for_call(setup.logical_call_id, extra=diagnostic_extra)
        if setup.strict_primary and fallback_status in {"not_attempted", "unavailable"}:
            fallback_remaining_ms = max(0, int((setup.task_deadline_at - time.monotonic()) * 1000))
            fallback_dimension = {
                "recovery_reserve_exhausted": "recovery_reserve",
                "not_eligible": "fallback_not_eligible",
                "circuit_open": "circuit_open",
                "retry_after_exceeds_deadline": "retry_after",
                "recovery_wait_exceeds_deadline": "recovery_wait",
                "same_provider_schema_retry_forbidden": "same_provider_schema_retry",
            }.get(fallback_block_reason, "fallback_disabled")
            diagnostic_extra.append(
                ModelAttemptSummary(
                    ordinal=max((item.ordinal for item in summaries), default=0) + 1,
                    stage=(
                        "fallback_budget"
                        if fallback_block_reason
                        in {
                            "recovery_reserve_exhausted",
                            "retry_after_exceeds_deadline",
                            "recovery_wait_exceeds_deadline",
                        }
                        else "fallback_gate"
                    ),
                    error_type="fallback_unavailable",
                    retryable=False,
                    route=setup.route.route,
                    route_profile=setup.route.fallback_profile,
                    model_id=setup.route.fallback.model_id,
                    prompt_version=setup.prompt_version,
                    deadline_ms=fallback_remaining_ms,
                    remaining_budget_ms=fallback_remaining_ms,
                    logical_call_id=setup.logical_call_id,
                    parent_logical_call_id=setup.parent_logical_call_id,
                    prompt_optimizer_attempt_id=setup.prompt_optimizer_attempt_id,
                    prompt_lineage_reason=setup.prompt_lineage_reason,
                    lineage_stage="fallback",
                    recovery_kind="fallback_unavailable",
                    recovery_independence="not_applicable",
                    budget_dimension=fallback_dimension,
                )
            )
            fallback_status = "unavailable"
        summaries = self._summaries_for_call(setup.logical_call_id, extra=diagnostic_extra)
        last_summary = summaries[-1] if summaries else None
        failure_summary = next(
            (item for item in reversed(summaries) if item.error_type != "fallback_unavailable"),
            last_summary,
        )
        failure = self._build_failure(
            logical_call_id=setup.logical_call_id,
            last_error=last_error,
            route=setup.route.route,
            route_profile=(setup.route.primary_profile if failure_summary is None else failure_summary.route_profile),
            model_id=setup.route.primary.model_id if failure_summary is None else failure_summary.model_id,
            prompt_version=setup.prompt_version,
            deadline_ms=deadline_ms,
            deadline_at=deadline_at,
            fallback_status=fallback_status,
            extra_attempts=diagnostic_extra,
        )
        safe_error = (
            "response byte limit exceeded" if failure.error_type == "response_too_large" else failure.error_type
        )
        gateway_error = ModelGatewayError(
            f"All configured models failed safely: {safe_error}",
            failure=failure,
        )
        if last_error is None:
            raise gateway_error
        raise gateway_error from last_error

    async def structured(
        self,
        *,
        role: str,
        system_prompt: str,
        user_prompt: str,
        output_model: type[T],
        prompt_version: str,
        run_id: str | None = None,
        prompt_artifact: PromptArtifact | None = None,
        durable_call_key: str | None = None,
        task_kind: ModelTaskKind | str | None = None,
        prompt_selection_digest: str | None = None,
        prompt_optimizer_attempt_id: str | None = None,
        prompt_lineage_reason: str | None = None,
        parent_logical_call_id: str | None = None,
        lineage_stage: str = "primary",
        thinking_enabled: bool | None = None,
        call_purpose: str = "auxiliary",
        step_id: str | None = None,
        worker_id: str | None = None,
    ) -> tuple[T, ModelCallMeta]:
        setup = self._prepare_structured_call(
            role=role,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            output_model=output_model,
            prompt_version=prompt_version,
            run_id=run_id,
            prompt_artifact=prompt_artifact,
            durable_call_key=durable_call_key,
            task_kind=task_kind,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
        )
        system_prompt = setup.system_prompt
        user_prompt = setup.user_prompt
        prompt_version = setup.prompt_version
        prompt_artifact_id = setup.prompt_artifact_id
        prompt_selection_digest = setup.prompt_selection_digest
        prompt_optimizer_attempt_id = setup.prompt_optimizer_attempt_id
        prompt_lineage_reason = setup.prompt_lineage_reason
        parent_logical_call_id = setup.parent_logical_call_id
        route = setup.route
        strict_primary = setup.strict_primary
        bounded_single_attempt = setup.bounded_single_attempt
        candidate_specs = setup.candidate_specs
        logical_started_at = setup.logical_started_at
        task_deadline_at = setup.task_deadline_at
        primary_header_deadline_at = setup.primary_header_deadline_at
        primary_stream_deadline_at = setup.primary_stream_deadline_at
        deadline_at = setup.deadline_at
        stream_deadline_at = setup.stream_deadline_at
        deadline_ms = setup.deadline_ms
        route_name = route.route
        diagnostic_extra: list[ModelAttemptSummary] = []
        fallback_status = "not_attempted"
        fallback_block_reason = "not_attempted"
        fallback_attempted = False
        fallback_guidance: str | None = None
        schema_repair_candidate: str | None = None
        last_error: BaseException | None = None
        response_schema = setup.response_schema
        response_schema_sha256 = setup.response_schema_sha256
        request_sha256 = setup.request_sha256
        logical_call_id = setup.logical_call_id
        attempt_sequence_floor = setup.attempt_sequence_floor
        replayed_usage = UsageProvenance()
        full_task_budget_ms = setup.full_task_budget_ms
        for index, (model_id, route_profile, used_fallback) in enumerate(candidate_specs):
            same_provider_lineage = (
                used_fallback and MODEL_CATALOG[route.primary.model_id].provider == MODEL_CATALOG[model_id].provider
            )
            if used_fallback and fallback_guidance in {
                "rate_limit",
                "http_5xx",
                "transport",
                "timeout",
                "circuit_open",
            }:
                wait = fallback_wait_decision(
                    guidance=fallback_guidance,
                    same_provider=same_provider_lineage,
                    live_mode=self.policy.mode is ModelMode.LIVE,
                    configured_backoff_seconds=self.settings.model_provider_recovery_backoff_seconds,
                    logical_call_id=logical_call_id,
                    attempts=self._summaries_for_call(logical_call_id, extra=diagnostic_extra),
                    remaining_seconds=max(0.0, task_deadline_at - time.monotonic()),
                )
                if wait.block_reason is not None:
                    fallback_status = "unavailable"
                    fallback_block_reason = wait.block_reason
                    break
                if wait.wait_seconds > 0:
                    await asyncio.sleep(wait.wait_seconds)
            recovery_kind = _recovery_kind(
                used_fallback=used_fallback,
                repair_index=0,
                fallback_guidance=fallback_guidance,
                primary_model_id=route.primary.model_id,
                model_id=model_id,
            )
            recovery_independence = _recovery_independence(
                recovery_kind=recovery_kind,
                same_model_lineage=same_provider_lineage,
            )
            fallback_output_cap: int | None = None
            circuit_permit: CircuitPermit | None = None
            if strict_primary:
                # Primary and fallback no longer share a single deadline.  A
                # Primary must preserve the configured recovery reserve, while
                # fallback may use the remaining task envelope.  A healthy
                # streaming Primary has a distinct bounded body deadline.
                deadline_at = task_deadline_at if used_fallback else primary_header_deadline_at
                stream_deadline_at = task_deadline_at if used_fallback else primary_stream_deadline_at
                if used_fallback:
                    fallback_remaining_ms = max(0, int((task_deadline_at - time.monotonic()) * 1000))
                    fallback_output_cap = self._fallback_output_cap(
                        remaining_budget_ms=fallback_remaining_ms,
                        full_task_budget_ms=full_task_budget_ms,
                    )
                    if fallback_output_cap <= 0:
                        fallback_status = "unavailable"
                        fallback_block_reason = "recovery_reserve_exhausted"
                        break
                    # Publish and reserve only the budget that exists at the
                    # moment fallback starts, rather than the original task
                    # envelope which the Primary may already have consumed.
                    deadline_ms = fallback_remaining_ms
                else:
                    deadline_ms = max(0, int((deadline_at - logical_started_at) * 1000))
            repair_prompt = user_prompt
            if strict_primary and used_fallback and fallback_guidance in {"schema", "parse"}:
                repair_prompt = schema_fallback_prompt(user_prompt, schema_repair_candidate)
            elif strict_primary and used_fallback:
                repair_prompt = infrastructure_fallback_prompt(user_prompt, guidance=fallback_guidance)
            # A HTTP 200 response gets one bounded local syntax recovery in
            # ``parse_model``. Never replay schema-invalid answer content to
            # the same provider as a paid network "repair".
            repair_limit = 0
            for repair_index in range(repair_limit + 1):
                recovery_kind = _recovery_kind(
                    used_fallback=used_fallback,
                    repair_index=repair_index,
                    fallback_guidance=fallback_guidance,
                    primary_model_id=route.primary.model_id,
                    model_id=model_id,
                )
                recovery_independence = _recovery_independence(
                    recovery_kind=recovery_kind,
                    same_model_lineage=same_provider_lineage,
                )
                slot_lineage_stage = (
                    lineage_stage
                    if lineage_stage != "primary"
                    else _lineage_stage(used_fallback=used_fallback, repair_index=repair_index)
                )
                payload = self._chat_payload(
                    model_id,
                    system_prompt,
                    repair_prompt,
                    response_schema,
                    route_profile=route_profile,
                    task_kind=route.task_kind,
                    max_output_tokens=fallback_output_cap,
                    thinking_enabled=thinking_enabled,
                )
                provider_request_sha256 = _canonical_sha256(
                    {
                        "endpoint": f"{self.policy.base_url}/chat/completions",
                        "payload": payload,
                    }
                )
                receipt: RawModelResponseReceipt | None = None
                raw: str | None = None
                replayed = False
                if durable_call_key is not None and run_id is not None:
                    receipt = self._load_raw_response_receipt(
                        run_id=run_id,
                        logical_call_id=logical_call_id,
                        model_id=model_id,
                        candidate_index=index,
                        repair_index=repair_index,
                        request_sha256=request_sha256,
                        provider_request_sha256=provider_request_sha256,
                        response_schema_sha256=response_schema_sha256,
                        prompt_version=prompt_version,
                        prompt_artifact_id=(None if prompt_artifact is None else prompt_artifact.artifact_id),
                        prompt_selection_digest=prompt_selection_digest,
                        prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                        prompt_lineage_reason=prompt_lineage_reason,
                        parent_logical_call_id=parent_logical_call_id,
                        lineage_stage=slot_lineage_stage,
                    )
                    if receipt is not None:
                        raw = self._read_raw_response(receipt)
                        replayed_usage = replayed_usage.merge(UsageProvenance.from_receipt(receipt))
                        replayed = True
                try:
                    if raw is None:
                        route_key = self._route_key(model_id, route_profile)
                        circuit_permit = self._circuit.acquire(route_key)
                        if circuit_permit is CircuitPermit.OPEN:
                            last_error = ModelGatewayError(f"Model circuit is open: {model_id}")
                            if used_fallback:
                                fallback_status = "unavailable"
                                fallback_block_reason = "circuit_open"
                            diagnostic_extra.append(
                                ModelAttemptSummary(
                                    ordinal=max(
                                        (
                                            item.ordinal
                                            for item in self._summaries_for_call(
                                                logical_call_id,
                                                extra=diagnostic_extra,
                                            )
                                        ),
                                        default=0,
                                    )
                                    + 1,
                                    stage="circuit",
                                    error_type="circuit_open",
                                    retryable=True,
                                    request_digest=provider_request_sha256,
                                    route=route_name,
                                    route_profile=route_profile,
                                    model_id=model_id,
                                    prompt_version=prompt_version,
                                    prompt_artifact_id=prompt_artifact_id,
                                    prompt_selection_digest=prompt_selection_digest,
                                    prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                                    prompt_lineage_reason=prompt_lineage_reason,
                                    parent_logical_call_id=parent_logical_call_id,
                                    lineage_stage=slot_lineage_stage,
                                    recovery_kind=recovery_kind,
                                    recovery_independence=recovery_independence,
                                    deadline_ms=deadline_ms,
                                    remaining_budget_ms=max(0, int((deadline_at - time.monotonic()) * 1000)),
                                    logical_call_id=logical_call_id,
                                )
                            )
                            break
                        if used_fallback:
                            fallback_attempted = True
                            fallback_status = "attempted"
                        slot_attempt_sequence_floor = self._provider_sequence
                        call_summaries = self._summaries_for_call(
                            logical_call_id,
                            extra=diagnostic_extra,
                        )
                        raw, duration_ms, provider_attempt = await self._request_with_retry(
                            model_id,
                            system_prompt,
                            repair_prompt,
                            response_schema,
                            run_id=run_id,
                            logical_call_id=logical_call_id,
                            payload=payload,
                            task_kind=route.task_kind.value,
                            lane=route.lane.value,
                            router_version=route.router_version,
                            prompt_version=prompt_version,
                            prompt_artifact_id=prompt_artifact_id,
                            prompt_selection_digest=prompt_selection_digest,
                            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                            prompt_lineage_reason=prompt_lineage_reason,
                            parent_logical_call_id=parent_logical_call_id,
                            lineage_stage=slot_lineage_stage,
                            recovery_kind=recovery_kind,
                            recovery_independence=recovery_independence,
                            deadline_at=deadline_at,
                            stream_deadline_at=stream_deadline_at,
                            deadline_ms=deadline_ms,
                            attempt_limit=1 if bounded_single_attempt else self.settings.model_max_attempts,
                            attempt_ordinal=max((item.ordinal for item in call_summaries), default=0) + 1,
                            route=route_name,
                            route_profile=route_profile,
                            normalize_errors=strict_primary,
                            snapshot_parent=SnapshotParent(run_id, "secmind", step_id, worker_id)
                            if run_id and call_purpose == "primary" else None,
                        )
                        if durable_call_key is not None and run_id is not None:
                            slot_attempts = [
                                item
                                for item in self._provider_attempts
                                if item.logical_call_id == logical_call_id
                                and item.sequence > slot_attempt_sequence_floor
                            ]
                            slot_usage = UsageProvenance.from_attempts(slot_attempts)
                            receipt = self._persist_raw_response_receipt(
                                raw=raw,
                                run_id=run_id,
                                logical_call_id=logical_call_id,
                                provider_attempt=provider_attempt,
                                model_id=model_id,
                                candidate_index=index,
                                repair_index=repair_index,
                                request_sha256=request_sha256,
                                provider_request_sha256=provider_request_sha256,
                                response_schema_sha256=response_schema_sha256,
                                prompt_version=prompt_version,
                                prompt_artifact_id=(None if prompt_artifact is None else prompt_artifact.artifact_id),
                                prompt_selection_digest=prompt_selection_digest,
                                prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                                prompt_lineage_reason=prompt_lineage_reason,
                                parent_logical_call_id=parent_logical_call_id,
                                lineage_stage=slot_lineage_stage,
                                duration_ms=duration_ms,
                                used_fallback=used_fallback,
                                usage=slot_usage.settled,
                                provider_reported_usage=slot_usage.provider_reported,
                                conservative_reserved_usage=slot_usage.conservative_reserved,
                                unknown_usage_attempts=slot_usage.unknown_attempts,
                            )
                            if receipt is not None:
                                # Always parse verified CAS bytes. A concurrent
                                # writer may have won this deterministic slot.
                                raw = self._read_raw_response(receipt)
                    else:
                        if used_fallback:
                            fallback_attempted = True
                            fallback_status = "attempted"
                        if receipt is None:  # pragma: no cover - guarded by the load branch
                            raise DurableReceiptError("raw response receipt was not loaded")
                        duration_ms = receipt.duration_ms
                    parsed = self._parse_model(raw, output_model)
                    self._circuit.record_success(self._route_key(model_id, route_profile))
                    call_attempts = [
                        item
                        for item in self._provider_attempts
                        if item.logical_call_id == logical_call_id and item.sequence > attempt_sequence_floor
                    ]
                    total_usage = replayed_usage.merge(UsageProvenance.from_attempts(call_attempts))
                    response_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                    return parsed, ModelCallMeta(
                        model_id=model_id,
                        prompt_version=prompt_version,
                        response_sha256=response_sha256,
                        duration_ms=duration_ms,
                        used_fallback=used_fallback,
                        usage=total_usage.settled,
                        logical_call_id=logical_call_id,
                        request_sha256=request_sha256,
                        response_schema_sha256=response_schema_sha256,
                        prompt_artifact_id="" if prompt_artifact is None else prompt_artifact.artifact_id,
                        prompt_selection_digest=("" if prompt_selection_digest is None else prompt_selection_digest),
                        prompt_optimizer_attempt_id=(
                            "" if prompt_optimizer_attempt_id is None else prompt_optimizer_attempt_id
                        ),
                        prompt_lineage_reason=prompt_lineage_reason,
                        parent_logical_call_id=parent_logical_call_id,
                        lineage_stage=slot_lineage_stage,
                        recovery_kind=recovery_kind,
                        recovery_independence=recovery_independence,
                        raw_response_artifact_id=("" if receipt is None else receipt.response_artifact_id),
                        replayed_from_receipt=replayed,
                        route_task_kind=route.task_kind.value,
                        route_lane=route.lane.value,
                        router_version=route.router_version,
                        route_rationale=route.rationale,
                        route_profile=route_profile,
                        deadline_ms=deadline_ms,
                        remaining_budget_ms=max(0, int((deadline_at - time.monotonic()) * 1000)),
                        attempts=tuple(self._summaries_for_call(logical_call_id, extra=diagnostic_extra)),
                        provider=MODEL_CATALOG[model_id].provider,
                        provider_reported_usage=total_usage.provider_reported,
                        conservative_reserved_usage=total_usage.conservative_reserved,
                        unknown_usage_attempts=total_usage.unknown_attempts,
                    )
                except DurableReceiptError:
                    raise
                except (ValidationError, json.JSONDecodeError) as exc:
                    last_error = exc
                    if strict_primary:
                        if raw is not None and raw.strip():
                            schema_repair_candidate = raw
                        diagnostic_extra.append(
                            self._schema_failure_summary(
                                self._summaries_for_call(logical_call_id, extra=diagnostic_extra),
                                route=route_name,
                                route_profile=route_profile,
                                model_id=model_id,
                                prompt_version=prompt_version,
                                deadline_ms=deadline_ms,
                                remaining_budget_ms=max(0, int((deadline_at - time.monotonic()) * 1000)),
                                logical_call_id=logical_call_id,
                                parent_logical_call_id=parent_logical_call_id,
                                prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
                                prompt_lineage_reason=prompt_lineage_reason,
                                lineage_stage=slot_lineage_stage,
                                recovery_kind=recovery_kind,
                                recovery_independence=recovery_independence,
                            )
                        )
                        break
                    if repair_index >= repair_limit:
                        break
                    repair_prompt = (
                        f"{user_prompt}\n\nYour previous response did not validate against the required JSON schema. "
                        "Return a complete JSON object only; do not omit, rename, or add fields."
                    )
                except (ModelGatewayError, httpx.TransportError) as exc:
                    # Tenacity re-raises the final transport exception after
                    # its bounded retry loop. Never leak provider-library
                    # exceptions across the model gateway boundary: callers
                    # need one typed failure in order to preserve a partial
                    # answer instead of crashing the graph.
                    last_error = exc
                    if isinstance(exc, ModelGatewayError) and exc.failure is not None:
                        diagnostic_extra.extend(item for item in exc.failure.attempts if item not in diagnostic_extra)
                    break
            route_key = self._route_key(model_id, route_profile)
            summaries = self._summaries_for_call(logical_call_id, extra=diagnostic_extra)
            breaker_category = self._failure_category(summaries[-1] if summaries else None, last_error)
            # An OPEN permit is an existing provider-scoped state, not a new
            # task-local failure.  Recording it as non-provider-scoped would
            # pop the cooldown state and let the next run probe immediately.
            if circuit_permit is not CircuitPermit.OPEN:
                retry_after_seconds = latest_retry_after_seconds(summaries)
                self._circuit.record_failure(
                    route_key,
                    provider_scoped=breaker_category in {"rate_limit", "http_5xx", "transport", "timeout"},
                    cooldown_seconds=(retry_after_seconds if breaker_category == "rate_limit" else None),
                )

            if strict_primary and not used_fallback:
                summaries = self._summaries_for_call(logical_call_id, extra=diagnostic_extra)
                last_summary = summaries[-1] if summaries else None
                category = self._failure_category(last_summary, last_error)
                fallback_guidance = category
                has_fallback = index + 1 < len(candidate_specs)
                next_provider = MODEL_CATALOG[candidate_specs[index + 1][0]].provider if has_fallback else ""
                eligibility = fallback_eligibility(
                    category=category,
                    has_fallback=has_fallback,
                    same_provider=MODEL_CATALOG[model_id].provider == next_provider,
                )
                if not eligibility.eligible:
                    fallback_status = "unavailable"
                    fallback_block_reason = eligibility.block_reason or "not_eligible"
                    break
            elif not strict_primary and index + 1 < len(candidate_specs):
                summaries = self._summaries_for_call(logical_call_id, extra=diagnostic_extra)
                category = self._failure_category(summaries[-1] if summaries else None, last_error)
                fallback_guidance = category
                next_model_id = candidate_specs[index + 1][0]
                eligibility = fallback_eligibility(
                    category=category,
                    has_fallback=True,
                    same_provider=(MODEL_CATALOG[model_id].provider == MODEL_CATALOG[next_model_id].provider),
                )
                if not eligibility.eligible:
                    break

        self._raise_structured_failure(
            setup=setup,
            fallback_attempted=fallback_attempted,
            fallback_status=fallback_status,
            fallback_block_reason=fallback_block_reason,
            diagnostic_extra=diagnostic_extra,
            last_error=last_error,
            deadline_at=deadline_at,
            deadline_ms=deadline_ms,
        )

    async def embeddings(self, texts: list[str], *, run_id: str | None = None) -> list[list[float]]:
        """Create embeddings for the Qdrant boundary without exposing provider details upstream."""
        return await run_embeddings(self, texts, run_id=run_id)

    def _max_output_tokens(
        self,
        route_profile: str,
        task_kind: ModelTaskKind | str | None = None,
    ) -> int:
        primary_limit = min(self.settings.model_max_output_tokens, self.settings.max_output_tokens)
        if task_kind is not None and ModelTaskKind(task_kind) is ModelTaskKind.PROMPT_OPTIMIZATION:
            return min(primary_limit, self.settings.prompt_optimizer_max_output_tokens)
        if route_profile == FALLBACK_ROUTE_PROFILE:
            # Keep the fallback provider-visible payload different even when
            # an operator accidentally configures both token budgets equally.
            return min(
                self.settings.model_fallback_max_output_tokens,
                max(128, primary_limit - 1),
                self.settings.max_output_tokens,
            )
        return primary_limit

    def _fallback_output_cap(self, *, remaining_budget_ms: int, full_task_budget_ms: int) -> int:
        """Scale fallback output to the wall-clock budget still available.

        The hard envelope is measured from logical-call start, so a fallback
        that starts late must not advertise the original 12k response budget to
        the provider.  The lower bound keeps a live fallback structurally
        useful; a non-positive remaining budget is rejected before transport.
        """

        configured = self._max_output_tokens(FALLBACK_ROUTE_PROFILE)
        if remaining_budget_ms <= 0:
            return 0
        if full_task_budget_ms <= 0:
            return configured
        scale = min(1.0, remaining_budget_ms / full_task_budget_ms)
        return max(128, min(configured, int(configured * scale)))

    def _chat_payload(
        self,
        model_id: str,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
        *,
        route_profile: str = PRIMARY_ROUTE_PROFILE,
        task_kind: ModelTaskKind | str | None = None,
        max_output_tokens: int | None = None,
        thinking_enabled: bool | None = None,
    ) -> dict[str, Any]:
        is_fallback = route_profile == FALLBACK_ROUTE_PROFILE
        max_output_tokens = (
            self._max_output_tokens(route_profile, task_kind)
            if max_output_tokens is None
            else max(128, min(max_output_tokens, self._max_output_tokens(route_profile, task_kind)))
        )
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_output_tokens,
        }
        provider = MODEL_CATALOG[model_id].provider
        if provider in {"dashscope", "deepseek"}:
            # DashScope and DeepSeek implement the portable JSON-object mode,
            # not OpenAI's stricter json_schema wire contract. The exact
            # schema remains explicit in the trusted system message and
            # Pydantic is still the final fail-closed validation boundary.
            payload["response_format"] = {"type": "json_object"}
            if provider == "deepseek":
                primary_thinking = (
                    self.settings.model_thinking_enabled
                    if thinking_enabled is None
                    else thinking_enabled
                )
                fallback_thinking = (
                    self.settings.model_fallback_thinking_enabled
                    if thinking_enabled is None
                    else thinking_enabled
                )
                payload.update(
                    {
                        "thinking": {
                            "type": (
                                "enabled"
                                if (fallback_thinking if is_fallback else primary_thinking)
                                else "disabled"
                            )
                        },
                        "reasoning_effort": (
                            self.settings.model_fallback_reasoning_effort
                            if is_fallback
                            else self.settings.model_reasoning_effort
                        ),
                    }
                )
            else:
                payload["temperature"] = 0
            payload["messages"] = [
                {
                    "role": "system",
                    "content": (
                        f"{system_prompt}\nReturn only one JSON object matching this JSON schema: "
                        f"{json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}"
                    ),
                },
                {"role": "user", "content": user_prompt},
            ]
        elif provider == "openai-compatible":
            payload["temperature"] = 0
            thinking_enabled = (
                self.settings.model_fallback_thinking_enabled if is_fallback else self.settings.model_thinking_enabled
            )
            if thinking_enabled:
                payload["reasoning_effort"] = (
                    self.settings.model_fallback_reasoning_effort
                    if is_fallback
                    else self.settings.model_reasoning_effort
                )
            structured_mode = self.settings.model_structured_output_mode
            if structured_mode == "json_object":
                # Some OpenAI-compatible gateways accept simple schemas but
                # reject the benchmark's larger json_schema document. Keep
                # the exact contract in the trusted prompt and retain Pydantic
                # as the fail-closed validation boundary.
                payload["response_format"] = {"type": "json_object"}
                payload["messages"] = [
                    {
                        "role": "system",
                        "content": (
                            f"{system_prompt}\nReturn only one JSON object matching this JSON schema: "
                            f"{json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}"
                        ),
                    },
                    {"role": "user", "content": user_prompt},
                ]
            else:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "secmind_output",
                        "schema": schema,
                    },
                }
        else:  # pragma: no cover - every reviewed chat provider is enumerated above
            raise ModelGatewayError(f"Provider {provider!r} has no reviewed structured-output mode")
        return payload

    def _load_raw_response_receipt(
        self,
        *,
        run_id: str,
        logical_call_id: str,
        model_id: str,
        candidate_index: int,
        repair_index: int,
        request_sha256: str,
        provider_request_sha256: str,
        response_schema_sha256: str,
        prompt_version: str,
        prompt_artifact_id: str | None,
        prompt_selection_digest: str | None,
        prompt_optimizer_attempt_id: str | None,
        prompt_lineage_reason: str,
        parent_logical_call_id: str | None,
        lineage_stage: str,
    ) -> RawModelResponseReceipt | None:
        return load_raw_response_receipt(
            self,
            run_id=run_id,
            logical_call_id=logical_call_id,
            model_id=model_id,
            candidate_index=candidate_index,
            repair_index=repair_index,
            request_sha256=request_sha256,
            provider_request_sha256=provider_request_sha256,
            response_schema_sha256=response_schema_sha256,
            prompt_version=prompt_version,
            prompt_artifact_id=prompt_artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            lineage_stage=lineage_stage,
        )

    def _persist_raw_response_receipt(
        self,
        *,
        raw: str,
        run_id: str,
        logical_call_id: str,
        provider_attempt: ProviderAttempt,
        model_id: str,
        candidate_index: int,
        repair_index: int,
        request_sha256: str,
        provider_request_sha256: str,
        response_schema_sha256: str,
        prompt_version: str,
        prompt_artifact_id: str | None,
        prompt_selection_digest: str | None,
        prompt_optimizer_attempt_id: str | None,
        prompt_lineage_reason: str,
        parent_logical_call_id: str | None,
        lineage_stage: str,
        duration_ms: int,
        used_fallback: bool,
        usage: ModelUsage,
        provider_reported_usage: ModelUsage,
        conservative_reserved_usage: ModelUsage,
        unknown_usage_attempts: int,
    ) -> RawModelResponseReceipt | None:
        return persist_raw_response_receipt(
            self,
            raw=raw,
            run_id=run_id,
            logical_call_id=logical_call_id,
            provider_attempt=provider_attempt,
            model_id=model_id,
            candidate_index=candidate_index,
            repair_index=repair_index,
            request_sha256=request_sha256,
            provider_request_sha256=provider_request_sha256,
            response_schema_sha256=response_schema_sha256,
            prompt_version=prompt_version,
            prompt_artifact_id=prompt_artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            lineage_stage=lineage_stage,
            duration_ms=duration_ms,
            used_fallback=used_fallback,
            usage=usage,
            provider_reported_usage=provider_reported_usage,
            conservative_reserved_usage=conservative_reserved_usage,
            unknown_usage_attempts=unknown_usage_attempts,
        )

    def _read_raw_response(self, receipt: RawModelResponseReceipt) -> str:
        return read_raw_response(self, receipt)

    async def _request_with_retry(
        self,
        model_id: str,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
        *,
        run_id: str | None,
        logical_call_id: str | None = None,
        payload: dict[str, Any] | None = None,
        task_kind: str = ModelTaskKind.GENERAL.value,
        lane: str = "lightweight",
        router_version: str = MODEL_ROUTER_VERSION,
        prompt_version: str,
        prompt_artifact_id: str | None = None,
        prompt_selection_digest: str | None = None,
        prompt_optimizer_attempt_id: str | None = None,
        prompt_lineage_reason: str = "legacy_unbound_prompt",
        parent_logical_call_id: str | None = None,
        lineage_stage: str = "legacy",
        recovery_kind: str = "primary",
        recovery_independence: str = "not_applicable",
        deadline_at: float | None = None,
        stream_deadline_at: float | None = None,
        deadline_ms: int = 0,
        attempt_limit: int | None = None,
        attempt_ordinal: int = 1,
        route: str | None = None,
        route_profile: str = PRIMARY_ROUTE_PROFILE,
        normalize_errors: bool = False,
        snapshot_parent: SnapshotParent | None = None,
    ) -> tuple[str, int, ProviderAttempt]:
        return await request_with_retry(
            self,
            model_id,
            system_prompt,
            user_prompt,
            schema,
            run_id=run_id,
            logical_call_id=logical_call_id,
            payload=payload,
            task_kind=task_kind,
            lane=lane,
            router_version=router_version,
            prompt_version=prompt_version,
            prompt_artifact_id=prompt_artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            lineage_stage=lineage_stage,
            recovery_kind=recovery_kind,
            recovery_independence=recovery_independence,
            deadline_at=deadline_at,
            stream_deadline_at=stream_deadline_at,
            deadline_ms=deadline_ms,
            attempt_limit=attempt_limit,
            attempt_ordinal=attempt_ordinal,
            route=route,
            route_profile=route_profile,
            normalize_errors=normalize_errors,
            snapshot_parent=snapshot_parent,
        )

    def _record_attempt(
        self,
        model_id: str,
        endpoint: str,
        started: float,
        status_code: int | None,
        succeeded: bool,
        retryable: bool,
        error_type: str | None,
        raw_usage: Any,
        *,
        run_id: str | None,
        reservation_id: str | None = None,
        logical_call_id: str | None = None,
        provider_request_sha256: str,
        task_kind: str = ModelTaskKind.GENERAL.value,
        lane: str = "lightweight",
        router_version: str = MODEL_ROUTER_VERSION,
        prompt_version: str,
        prompt_artifact_id: str | None = None,
        prompt_selection_digest: str | None = None,
        prompt_optimizer_attempt_id: str | None = None,
        prompt_lineage_reason: str = "legacy_unbound_prompt",
        parent_logical_call_id: str | None = None,
        lineage_stage: str = "legacy",
        recovery_kind: str = "primary",
        recovery_independence: str = "not_applicable",
        response_sha256: str | None,
        ordinal: int = 0,
        stage: str = "provider",
        deadline_ms: int = 0,
        remaining_budget_ms: int = 0,
        route: str | None = None,
        route_profile: str = PRIMARY_ROUTE_PROFILE,
        estimated_input_tokens: int = 0,
        estimated_output_tokens: int = 0,
        retry_after_ms: int | None = None,
        retry_after_source: Literal["delta_seconds", "http_date"] | None = None,
    ) -> ProviderAttempt:
        return record_attempt(
            self,
            model_id,
            endpoint,
            started,
            status_code,
            succeeded,
            retryable,
            error_type,
            raw_usage,
            run_id=run_id,
            reservation_id=reservation_id,
            logical_call_id=logical_call_id,
            provider_request_sha256=provider_request_sha256,
            task_kind=task_kind,
            lane=lane,
            router_version=router_version,
            prompt_version=prompt_version,
            prompt_artifact_id=prompt_artifact_id,
            prompt_selection_digest=prompt_selection_digest,
            prompt_optimizer_attempt_id=prompt_optimizer_attempt_id,
            prompt_lineage_reason=prompt_lineage_reason,
            parent_logical_call_id=parent_logical_call_id,
            lineage_stage=lineage_stage,
            recovery_kind=recovery_kind,
            recovery_independence=recovery_independence,
            response_sha256=response_sha256,
            ordinal=ordinal,
            stage=stage,
            deadline_ms=deadline_ms,
            remaining_budget_ms=remaining_budget_ms,
            route=route,
            route_profile=route_profile,
            estimated_input_tokens=estimated_input_tokens,
            estimated_output_tokens=estimated_output_tokens,
            retry_after_ms=retry_after_ms,
            retry_after_source=retry_after_source,
        )

    def _reserve_provider_attempt(
        self,
        run_id: str | None,
        model_id: str,
        endpoint: str,
        *,
        input_bytes: int,
        output_tokens: int,
    ) -> str | None:
        if self._usage_store is None or run_id is None:
            return None
        reservation_id = str(uuid4())
        # The root envelope remains deterministic because it represents one
        # run, while every actual provider attempt receives a collision-free
        # durable identity across process restarts.
        root_id = str(uuid5(NAMESPACE_URL, f"secmind:budget:{run_id}:root"))
        estimated_input_tokens = estimate_prompt_tokens(input_bytes)
        reserved_cost = self._cost_units(model_id, estimated_input_tokens, output_tokens)
        self._usage_store.reserve_usage(
            seal_contract(
                UsageReservation,
                reservation_id=root_id,
                run_id=run_id,
                transition_id=f"run:{run_id}:budget-root",
                kind="run",
                tool_calls=self.settings.max_tool_calls,
                provider_requests=self.settings.max_provider_requests,
                input_tokens=self.settings.max_input_tokens,
                output_tokens=self.settings.max_output_tokens,
                cost_units=self.settings.max_cost_units,
                wall_time_ms=self.settings.max_runtime_seconds * 1000,
                artifact_bytes=self.settings.max_tool_calls * 16 * 1024 * 1024,
            )
        )
        self._usage_store.reserve_usage(
            seal_contract(
                UsageReservation,
                reservation_id=reservation_id,
                run_id=run_id,
                parent_reservation_id=root_id,
                transition_id=f"model:{reservation_id}",
                kind="model",
                provider_requests=1,
                input_tokens=estimated_input_tokens,
                output_tokens=output_tokens,
                cost_units=reserved_cost,
                wall_time_ms=int(self.settings.model_timeout_seconds * 1000),
            )
        )
        return reservation_id

    def _cost_units(self, model_id: str, input_tokens: int, output_tokens: int) -> float:
        entries = (
            self.policy.planner,
            self.policy.worker,
            self.policy.fallback,
            self.policy.embedding,
        )
        return cost_units(
            model_id,
            input_tokens,
            output_tokens,
            model_tiers=tuple((item.model_id, item.tier) for item in entries),
            default_tier=self.settings.max_model_tier,
        )

    def _parse_model(self, raw: str, output_model: type[T]) -> T:
        return parse_model(
            raw,
            output_model,
            max_chars=self.settings.model_json_recovery_max_chars,
            max_depth=self.settings.model_json_recovery_max_depth,
        )


async def close_gateway_safely(gateway: QwenGateway) -> None:
    try:
        await gateway.close()
    except (httpx.HTTPError, asyncio.CancelledError):
        pass
