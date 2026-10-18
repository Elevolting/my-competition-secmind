"""ToolBroker control-plane facade and durable bookkeeping helpers."""

from __future__ import annotations

# ruff: noqa: F401,F403,F405
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx

from secmind.artifact_store import ArtifactStoreError, ContentAddressedArtifactStore
from secmind.coordinator import CoordinatorStore
from secmind.execution import ExecutionConflict, ExecutionStore, parameters_hash
from secmind.guardrail import Guardrail, GuardrailAction, GuardrailDecision
from secmind.hook_bus import HookBus, HookExecutionError
from secmind.investigation.contracts import (
    ArtifactDataClass,
    ArtifactSecurityLabel,
    ArtifactView,
    DispatchPermit,
    ExecutionIdentity,
    seal_contract,
)
from secmind.investigation.store import InvestigationStore
from secmind.ledger import LedgerStore, canonical_json, redact
from secmind.metrics import TOOL_CALLS
from secmind.policy import PolicyDecisionPoint, manifest_digest
from secmind.schemas import *
from secmind.secret_scrubber import scrub_text, scrub_value
from secmind.tool_assurance import build_tool_assurance
from secmind.tooling.broker_execution import execute_tool
from secmind.tooling.core import ToolInvocationIdentityError, ToolValidationError
from secmind.tooling.registry import ToolRegistry
from secmind.unit_of_work import ControlPlaneUnitOfWork, UnitOfWorkConflict


class ToolBroker:
    def __init__(
        self,
        registry: ToolRegistry,
        guardrail: Guardrail,
        execution_store: ExecutionStore | None = None,
        ledger: LedgerStore | None = None,
        coordinator: CoordinatorStore | None = None,
        unit_of_work: ControlPlaneUnitOfWork | None = None,
        policy_decision_point: PolicyDecisionPoint | None = None,
        artifact_store: ContentAddressedArtifactStore | None = None,
        hook_bus: HookBus | None = None,
        owned_async_clients: list[httpx.AsyncClient] | None = None,
        investigation_store: InvestigationStore | None = None,
    ) -> None:
        self.registry = registry
        self.guardrail = guardrail
        self.execution_store = execution_store or ExecutionStore()
        self.ledger = ledger
        self.coordinator = coordinator
        self.unit_of_work = unit_of_work
        self.policy_decision_point = policy_decision_point or PolicyDecisionPoint()
        self.artifact_store = artifact_store
        self.hook_bus = hook_bus or HookBus()
        self._owned_async_clients = tuple(owned_async_clients or ())
        self.investigation_store = investigation_store

    def assess(self, name: str, args: dict[str, Any], autonomy_policy: str) -> GuardrailDecision:
        return self.guardrail.evaluate(self.registry.get(name).manifest, args, autonomy_policy)

    def register_approval(self, request: ApprovalRequest) -> None:
        self.execution_store.register_approval(request)

    def resolve_approval(
        self,
        request_id: str,
        response: ApprovalResponse,
        *,
        actor: str = "local-operator",
        run_id: str | None = None,
        fence: int = 0,
    ) -> str:
        return self.execution_store.resolve_approval(
            request_id,
            response,
            actor=actor,
            run_id=run_id,
            fence=fence,
        )

    def consume_approval(
        self,
        request_id: str,
        *,
        run_id: str,
        step_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        fence: int,
        resolution_id: str,
    ) -> str:
        return self.execution_store.consume_approval(
            request_id,
            run_id=run_id,
            step_id=step_id,
            tool_name=tool_name,
            parameters=parameters,
            fence=fence,
            resolution_id=resolution_id,
        )

    def approval_response(self, request_id: str, *, run_id: str) -> ApprovalResponse:
        return self.execution_store.approval_response(request_id, run_id=run_id)

    def active_invocation_ids(self, run_id: str) -> list[str]:
        return self.execution_store.active_invocation_ids(run_id)

    async def execute(
        self,
        name: str,
        args: dict[str, Any],
        context: ToolContext,
        *,
        autonomy_policy: str = "graded",
        approval_request_id: str | None = None,
    ) -> ToolResult:
        """Validate policy, approval and idempotency before crossing the tool boundary."""
        return await execute_tool(
            self,
            name,
            args,
            context,
            autonomy_policy=autonomy_policy,
            approval_request_id=approval_request_id,
        )

    def _cached_execution_identity_is_valid(
        self,
        result: ToolResult,
        context: ToolContext,
        manifest: ToolManifest,
    ) -> bool:
        if (
            self.investigation_store is None
            or context.step_run_id is None
            or context.run_fence <= 0
            or context.step_fence <= 0
        ):
            return True
        if result.invocation_id is None:
            return False
        identity = self.investigation_store.execution_identity(result.invocation_id, run_id=context.run_id)
        if identity is None:
            return False
        output_digest = hashlib.sha256(canonical_json(result.model_dump(mode="json")).encode()).hexdigest()
        return bool(
            identity.step_run_id == context.step_run_id
            and identity.run_fence == context.run_fence
            and identity.step_fence == context.step_fence
            and identity.actual_tool_name == manifest.name
            and identity.actual_tool_version == manifest.version
            and identity.output_digest == output_digest
        )

    def _record_execution_identity(
        self,
        *,
        result: ToolResult,
        context: ToolContext,
        manifest: ToolManifest,
        invocation_attempt: int,
        envelope: ToolInputEnvelope,
        invocation_started_at: datetime,
    ) -> None:
        if (
            self.investigation_store is None
            or context.step_run_id is None
            or context.run_fence <= 0
            or context.step_fence <= 0
        ):
            return
        output_digest = hashlib.sha256(canonical_json(result.model_dump(mode="json")).encode()).hexdigest()
        self.investigation_store.record_execution_identity(
            seal_contract(
                ExecutionIdentity,
                digest_field="identity_digest",
                invocation_id=context.invocation_id,
                attempt=max(1, invocation_attempt),
                run_id=context.run_id,
                step_run_id=context.step_run_id,
                run_fence=context.run_fence,
                step_fence=context.step_fence,
                actual_tool_name=manifest.name,
                actual_tool_version=manifest.version,
                image_digest=manifest.execution.image_digest,
                rule_bundle_digest=manifest.rule_bundle_digest,
                advisory_digest=None,
                input_digest=envelope.execution_digest,
                output_digest=output_digest,
                artifact_ids=[item.artifact_id for item in result.artifacts],
                started_at=invocation_started_at,
                settled_at=datetime.now(UTC),
            )
        )

    async def _apply_hooks(
        self,
        stage: str,
        *,
        name: str,
        args: dict[str, Any],
        context: ToolContext,
        allow_patch: bool,
    ) -> tuple[dict[str, Any], list[InputMutation], str | None]:
        observable = scrub_value(args)
        observable_input = observable if isinstance(observable, dict) else {}
        input_digest = hashlib.sha256(canonical_json(observable_input).encode()).hexdigest()
        event_id = str(
            uuid5(
                NAMESPACE_URL,
                f"secmind:hook:{context.run_id}:{context.idempotency_key}:{stage}:{input_digest}",
            )
        )
        event = HookEvent(
            event_id=event_id,
            run_id=context.run_id,
            step_id=context.step_id,
            event_type=stage,
            payload={
                "tool_name": name,
                "idempotency_key": context.idempotency_key,
                "observable_input": observable_input,
            },
        )
        try:
            results = await self.hook_bus.dispatch(event)
            if self.unit_of_work is not None:
                self.unit_of_work.record_hook_executions(event, results)
        except (HookExecutionError, UnitOfWorkConflict) as exc:
            return args, [], f"Hook validation failed closed: {exc}"
        current = json.loads(canonical_json(args))
        mutations: list[InputMutation] = []
        for result in results:
            self._append(
                context,
                "hook.executed",
                {
                    "hook_id": result.hook_id,
                    "event_id": result.event_id,
                    "stage": stage,
                    "decision": result.decision.value,
                    "input_hash": result.input_hash,
                    "output_hash": result.output_hash,
                    "error": result.error,
                },
                f"hook:{result.event_id}:{result.hook_id}:executed",
            )
            if result.decision == HookDecision.DENY:
                return current, mutations, f"Hook {result.hook_id} denied the invocation"
            if result.decision == HookDecision.REQUIRE_APPROVAL:
                return current, mutations, "Hooks cannot create approval authority; the PDP must decide"
            if result.decision != HookDecision.PATCH:
                continue
            if not allow_patch:
                return current, mutations, "A late hook patch invalidated the authorization binding"
            previous = json.loads(canonical_json(current))
            current.update(result.patch)
            for field in sorted(result.patch):
                mutations.append(
                    InputMutation(
                        stage="trusted_hook_patch",
                        field_path=str(field),
                        previous_digest=hashlib.sha256(canonical_json(previous.get(field)).encode()).hexdigest(),
                        new_digest=hashlib.sha256(canonical_json(current.get(field)).encode()).hexdigest(),
                        actor=f"hook:{result.hook_id}",
                        reason="A signed deterministic hook patched non-protected tool input before PDP evaluation.",
                        policy_ids=list(result.policy_ids),
                    )
                )
        return current, mutations, None

    def _bind_input_envelope(
        self,
        *,
        original_args: dict[str, Any],
        execution_args: dict[str, Any],
        mutations: list[InputMutation],
        context: ToolContext,
        approval_request_id: str | None,
    ) -> ToolInputEnvelope:
        raw_bytes = canonical_json(original_args).encode()
        execution_bytes = canonical_json(execution_args).encode()
        observable_value = scrub_value(execution_args)
        observable = observable_value if isinstance(observable_value, dict) else {}
        observable_bytes = canonical_json(observable).encode()
        raw_digest = hashlib.sha256(raw_bytes).hexdigest()
        execution_digest = hashlib.sha256(execution_bytes).hexdigest()
        observable_digest = hashlib.sha256(observable_bytes).hexdigest()
        raw_ref = raw_digest
        execution_ref = execution_digest
        if self.artifact_store is not None:
            raw_ref = self.artifact_store.put(
                raw_bytes,
                media_type="application/vnd.secmind.raw-tool-input+json",
                run_id=context.run_id,
                data_view=DataView.RAW_RESTRICTED,
                log_layer=LogLayer.RAW_SECURITY,
            ).artifact_id
            execution_ref = self.artifact_store.put(
                execution_bytes,
                media_type="application/vnd.secmind.execution-tool-input+json",
                run_id=context.run_id,
                data_view=DataView.RAW_RESTRICTED,
                log_layer=LogLayer.RAW_SECURITY,
            ).artifact_id
            if self.investigation_store is not None:
                input_artifacts = {
                    raw_ref: len(raw_bytes),
                    execution_ref: len(execution_bytes),
                }
                for artifact_id, payload_size in sorted(input_artifacts.items()):
                    self.investigation_store.label_artifact(
                        ArtifactSecurityLabel(
                            artifact_id=artifact_id,
                            owner_run_id=context.run_id,
                            owner_step_id=context.step_id,
                            owner_invocation_id=context.invocation_id,
                            view=ArtifactView.RAW_RESTRICTED,
                            data_class=ArtifactDataClass.TOOL_INPUT,
                            retention_policy_id="competition-run-default",
                            allowed_purposes=["analysis", "execution"],
                            created_by="tool-broker",
                            content_sha256=artifact_id,
                            size=payload_size,
                            media_type="application/vnd.secmind.tool-input+json",
                        )
                    )
        return ToolInputEnvelope(
            invocation_id=context.invocation_id,
            run_id=context.run_id,
            step_id=context.step_id,
            raw_input_ref=raw_ref,
            observable_input=observable,
            execution_input_ref=execution_ref,
            raw_digest=raw_digest,
            observable_digest=observable_digest,
            execution_digest=execution_digest,
            mutation_chain=mutations,
            scope_binding=list(context.allowed_paths),
            approval_binding=approval_request_id,
        )

    def close(self) -> None:
        self.execution_store.close()

    async def aclose(self) -> None:
        for client in self._owned_async_clients:
            await client.aclose()

    def _persist_result_artifacts(self, result: ToolResult, context: ToolContext) -> ToolResult:
        if self.artifact_store is None:  # pragma: no cover - caller guards this path
            return result
        artifacts = {item.artifact_id: item for item in result.artifacts}
        # Runner-produced bytes are untrusted even when their digest is valid.  A
        # digest proves identity, not that the payload is safe to expose.  Keep
        # these objects raw/restricted until a server-owned projection scrubs and
        # re-materializes them.
        raw_artifact_ids = set(artifacts)
        for artifact in tuple(artifacts.values()):
            if artifact.ref != artifact.artifact_id:
                raise ToolValidationError("tool artifact reference is not content-addressed")
            try:
                content = self.artifact_store.read(artifact.artifact_id)
            except (ArtifactStoreError, OSError) as exc:
                raise ToolValidationError("tool artifact is absent from the immutable ArtifactStore") from exc
            if len(content) != artifact.size_bytes or hashlib.sha256(content).hexdigest() != artifact.sha256:
                raise ToolValidationError("tool artifact metadata does not match immutable content")
            self.artifact_store.classify(
                artifact.artifact_id,
                run_id=context.run_id,
                data_view=DataView.RAW_RESTRICTED,
                log_layer=LogLayer.RAW_SECURITY,
                media_type=artifact.media_type,
            )
        evidence_items: list[Evidence] = []
        for evidence in result.evidence:
            body = json.dumps(
                redact(
                    {
                        "evidence_id": evidence.evidence_id,
                        "source": evidence.source,
                        "summary": evidence.summary,
                        "metadata": evidence.metadata,
                    }
                ),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            stored = self.artifact_store.put(
                body,
                media_type="application/vnd.secmind.evidence+json",
                run_id=context.run_id,
                data_view=DataView.OBSERVABLE,
            )
            evidence_items.append(
                evidence.model_copy(update={"artifact_ref": stored.artifact_id, "sha256": stored.sha256})
            )
            artifacts.setdefault(
                stored.artifact_id,
                ArtifactRef(
                    artifact_id=stored.artifact_id,
                    ref=stored.artifact_id,
                    sha256=stored.sha256,
                    size_bytes=stored.size_bytes,
                    media_type=stored.media_type,
                ),
            )
        persisted = result.model_copy(
            update={
                "evidence": evidence_items,
                "artifacts": sorted(artifacts.values(), key=lambda item: item.artifact_id),
            }
        )
        if self.investigation_store is not None:
            for artifact in persisted.artifacts:
                raw_restricted = artifact.artifact_id in raw_artifact_ids
                self.investigation_store.label_artifact(
                    ArtifactSecurityLabel(
                        artifact_id=artifact.artifact_id,
                        owner_run_id=context.run_id,
                        owner_step_id=context.step_id,
                        owner_invocation_id=context.invocation_id,
                        view=(ArtifactView.RAW_RESTRICTED if raw_restricted else ArtifactView.OBSERVABLE),
                        data_class=ArtifactDataClass.TOOL_OUTPUT,
                        retention_policy_id="competition-run-default",
                        allowed_purposes=(
                            ["analysis", "forensics"] if raw_restricted else ["analysis", "report", "download"]
                        ),
                        created_by="tool-broker",
                        content_sha256=artifact.sha256,
                        size=artifact.size_bytes,
                        media_type=artifact.media_type,
                    )
                )
        return persisted

    @staticmethod
    def _denied(context: ToolContext, code: str, message: str) -> ToolResult:
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.DENIED,
            error_code=code,
            error_message=message,
        )

    def _append(self, context: ToolContext, event_type: str, payload: dict[str, Any], dedupe_key: str) -> None:
        if self.coordinator is not None:
            self.coordinator.enqueue_outbox(
                context.run_id,
                transition_id=dedupe_key,
                event_type=event_type,
                payload=payload,
                actor="tool-broker",
                lease_owner_id=context.lease_owner_id,
                lease_fence=context.lease_fence,
            )
        elif self.ledger is not None:
            self.ledger.append(context.run_id, event_type, payload, actor="tool-broker", dedupe_key=dedupe_key)
