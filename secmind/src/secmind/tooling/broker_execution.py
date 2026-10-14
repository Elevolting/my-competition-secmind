"""Execution phase for the ToolBroker.

The broker class delegates its sole public execution entry point here so policy,
approval, idempotency, fence, hook, and ledger ordering remain one auditable
sequence while the facade stays small.
"""

from __future__ import annotations

# ruff: noqa: F401,F403,F405
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from secmind.artifact_store import ArtifactStoreError
from secmind.coordinator import CoordinatorStore
from secmind.execution import ExecutionConflict, parameters_hash
from secmind.guardrail import GuardrailAction
from secmind.investigation.contracts import DispatchPermit
from secmind.ledger import canonical_json, redact
from secmind.metrics import TOOL_CALLS
from secmind.policy import PolicyInput, manifest_digest
from secmind.schemas import *
from secmind.secret_scrubber import REDACTED, _key_tokens, scrub_text
from secmind.skill_usage import tool_usage
from secmind.tooling.core import ToolError, ToolInvocationIdentityError, ToolValidationError, _policy_path
from secmind.unit_of_work import UnitOfWorkConflict

_BARE_CAS_DIGEST = re.compile(r"^[a-fA-F0-9]{64}$")


def _is_untyped_artifact_reference_key(key: str) -> bool:
    tokens = _key_tokens(key)
    return bool(tokens) and "artifact" in tokens and tokens[-1] in {"id", "ids", "ref", "refs"}


def _scrub_untyped_artifact_references(value: Any) -> Any:
    """Remove bare CAS-looking refs from untyped tool payloads.

    Public contract identifiers are intentionally supported by the global
    scrubber.  Tool data and evidence metadata are a stricter boundary: an
    attacker-controlled ``artifact_id``/``artifact_ref`` must not become an
    implicit allowlist entry merely because it is 64-hex.  Typed
    ``ToolResult.artifacts`` are restored separately only after CAS validation.
    """

    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if _is_untyped_artifact_reference_key(str(key)):
                output[key] = _scrub_untyped_artifact_reference_value(item)
            else:
                output[key] = _scrub_untyped_artifact_references(item)
        return output
    if isinstance(value, list):
        return [_scrub_untyped_artifact_references(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_untyped_artifact_references(item) for item in value)
    return value


def _scrub_untyped_artifact_reference_value(value: Any) -> Any:
    if isinstance(value, str) and _BARE_CAS_DIGEST.fullmatch(value):
        return REDACTED
    if isinstance(value, list):
        return [_scrub_untyped_artifact_reference_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_untyped_artifact_reference_value(item) for item in value)
    if isinstance(value, dict):
        return _scrub_untyped_artifact_references(value)
    return value


def _sanitize_tool_result(result: ToolResult, *, artifact_store: Any | None) -> ToolResult:
    """Scrub a tool result while preserving only verified CAS artifact refs.

    ``redact`` deliberately treats opaque 64-hex strings as secrets unless a
    digest-labelled field proves otherwise.  That is the right default for
    arbitrary tool data, but it cannot be applied to the typed
    :class:`ArtifactRef` list: the broker must hand the server-owned projection
    the exact immutable identity it just verified.  Keep this exception here,
    at the tooling boundary, rather than weakening the global scrubber for
    every ``artifact_id``-shaped business field.
    """

    safe_payload = redact(result.model_dump(mode="python"))
    # The global scrubber intentionally preserves several public identifier
    # shapes.  Keep that policy for ordinary contract objects, but not for
    # untyped tool data/metadata where a caller can manufacture an
    # ``artifact_id`` key.  Typed refs are restored below only after CAS reads.
    safe_payload["data"] = _scrub_untyped_artifact_references(safe_payload.get("data", {}))
    safe_evidence = safe_payload.get("evidence")
    if isinstance(safe_evidence, list):
        for safe_item in safe_evidence:
            if isinstance(safe_item, dict):
                safe_item["metadata"] = _scrub_untyped_artifact_references(safe_item.get("metadata", {}))
    if artifact_store is None or not result.artifacts:
        return ToolResult.model_validate(safe_payload)

    verified_ids: set[str] = set()
    safe_artifacts: list[dict[str, Any]] = []
    for artifact in result.artifacts:
        # ArtifactRef.ref is an immutable CAS identity in broker results.  A
        # path-like or independently supplied ref must never be restored after
        # generic redaction, even if artifact_id happens to be valid.
        if artifact.ref != artifact.artifact_id:
            raise ToolValidationError("tool artifact reference is not content-addressed")
        try:
            content = artifact_store.read(artifact.artifact_id)
        except (ArtifactStoreError, OSError) as exc:
            raise ToolValidationError("tool artifact is absent from the immutable ArtifactStore") from exc
        if len(content) != artifact.size_bytes or hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise ToolValidationError("tool artifact metadata does not match immutable content")
        verified_ids.add(artifact.artifact_id)
        safe_artifacts.append(
            {
                "artifact_id": artifact.artifact_id,
                "ref": artifact.ref,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "media_type": scrub_text(artifact.media_type),
            }
        )
    safe_payload["artifacts"] = safe_artifacts

    # Evidence metadata remains fully scrubbed.  Only a link to an artifact
    # that was just CAS-verified above may be restored; a free-form
    # ``artifact_ref`` in evidence is not trusted merely because it resembles
    # a digest.
    if isinstance(safe_evidence, list):
        for evidence, safe_item in zip(result.evidence, safe_evidence, strict=False):
            if isinstance(safe_item, dict):
                if evidence.artifact_ref in verified_ids:
                    safe_item["artifact_ref"] = evidence.artifact_ref
    return ToolResult.model_validate(safe_payload)


async def execute_tool(
    broker: Any,
    name: str,
    args: dict[str, Any],
    context: ToolContext,
    *,
    autonomy_policy: str = "graded",
    approval_request_id: str | None = None,
) -> ToolResult:
    """Validate policy, approval and idempotency before crossing the tool boundary."""
    tool = broker.registry.get(name)
    manifest = tool.manifest
    try:
        original_args = json.loads(canonical_json(args))
    except (TypeError, ValueError) as exc:
        return broker._denied(context, "TOOL_INPUT_INVALID", scrub_text(str(exc)))
    mutations: list[InputMutation] = []
    try:
        broker.registry.validate_input(name, args)
    except ToolValidationError as exc:
        return broker._denied(context, "TOOL_INPUT_INVALID", str(exc))
    # Hooks and policy projections are durable side effects. Fence before
    # either stage so an expired worker cannot append audit data or mutate
    # invocation control state after ownership has moved on.
    if broker.coordinator is not None:
        broker.coordinator.assert_lease(
            context.run_id,
            owner_id=context.lease_owner_id,
            fence=context.lease_fence,
        )
    args, hook_mutations, hook_error = await broker._apply_hooks(
        "before_policy",
        name=name,
        args=args,
        context=context,
        allow_patch=True,
    )
    mutations.extend(hook_mutations)
    if hook_error is not None:
        return broker._denied(context, "HOOK_DENIED", hook_error)
    try:
        broker.registry.validate_input(name, args)
    except ToolValidationError as exc:
        return broker._denied(context, "HOOK_PATCH_INVALID", str(exc))

    policy_grant_id: str | None = None
    if broker.unit_of_work is not None:
        target = str(args.get("target", "."))
        resource = _policy_path(target, base=context.workspace)
        current_grants = broker.unit_of_work.grants_for_run(context.run_id)
        replay_grant = broker.unit_of_work.grant_bound_to_invocation(context.run_id, context.idempotency_key)
        if replay_grant is not None and all(item.grant_id != replay_grant.grant_id for item in current_grants):
            current_grants.append(replay_grant)
        policy_input = PolicyInput(
            policy_version=broker.policy_decision_point.policy_version,
            actor=context.lease_owner_id,
            run_id=context.run_id,
            step_id=context.step_id,
            action="execute",
            resource=resource,
            target_scope=[_policy_path(path) for path in context.allowed_paths],
            task_constraints=[autonomy_policy],
            tool_manifest_digest=manifest_digest(manifest),
            parameters_hash=parameters_hash(args),
            data_classification=DataSensitivity.INTERNAL,
            network_policy=manifest.execution.network_policy,
            workspace_policy={"allowed_paths": context.allowed_paths},
            requested_capabilities=sorted(set(manifest.capability_tags) | set(manifest.permissions)),
            current_grants=current_grants,
            fence=context.lease_fence,
        )
        policy_decision = broker.policy_decision_point.evaluate(policy_input, manifest)
        if policy_decision.action == PolicyAction.DENY:
            return broker._denied(context, "POLICY_DENIED", policy_decision.reason_summary)
        if policy_decision.action == PolicyAction.REQUIRE_APPROVAL:
            return broker._denied(context, "APPROVAL_REQUIRED", policy_decision.reason_summary)
        if policy_decision.capability_grant is not None:
            policy_grant_id = policy_decision.capability_grant.grant_id
        requires_grant = policy_decision.effective_risk == RiskLevel.R2
    else:
        decision = broker.guardrail.evaluate(manifest, args, autonomy_policy)
        if decision.action == GuardrailAction.DENY:
            return broker._denied(context, "GUARDRAIL_DENIED", decision.reason)
        if decision.action == GuardrailAction.REQUIRE_APPROVAL:
            approved = approval_request_id and broker.execution_store.approval_authorizes(
                approval_request_id,
                run_id=context.run_id,
                step_id=context.step_id,
                tool_name=name,
                parameters=args,
            )
            if not approved:
                return broker._denied(context, "APPROVAL_REQUIRED", decision.reason)
        requires_grant = False

    args, runner_mutations, hook_error = await broker._apply_hooks(
        "before_runner",
        name=name,
        args=args,
        context=context,
        allow_patch=False,
    )
    mutations.extend(runner_mutations)
    if hook_error is not None:
        return broker._denied(context, "HOOK_DENIED", hook_error)

    # Replays still pass through hooks and policy, but a completed logical
    # invocation must return before emitting a second input binding with a
    # new transport-level invocation_id.
    if broker.unit_of_work is not None:
        try:
            cached_result = broker.unit_of_work.cached_tool_result(
                run_id=context.run_id,
                idempotency_key=context.idempotency_key,
                tool_name=name,
                tool_version=manifest.version,
                parameters=args,
            )
        except ExecutionConflict as exc:
            return broker._denied(context, "IDEMPOTENCY_CONFLICT", str(exc))
        if cached_result is not None:
            if not broker._cached_execution_identity_is_valid(cached_result, context, manifest):
                return ToolResult(
                    invocation_id=cached_result.invocation_id,
                    status=ToolStatus.ERROR,
                    error_code="RECOVERY_REQUIRED",
                    error_message="Cached tool result has no matching durable execution identity.",
                )
            return cached_result

    envelope = broker._bind_input_envelope(
        original_args=original_args,
        execution_args=args,
        mutations=mutations,
        context=context,
        approval_request_id=approval_request_id,
    )
    if broker.unit_of_work is not None:
        try:
            broker.unit_of_work.record_tool_input_envelope(envelope)
        except UnitOfWorkConflict as exc:
            return broker._denied(context, "INPUT_BINDING_CONFLICT", str(exc))
    # Input envelopes are a v0.5 control-plane projection.  The legacy
    # SQLite-only broker keeps its historical event contract and relies on
    # ExecutionStore.claim_invocation() for deduplication.
    if broker.unit_of_work is not None or mutations:
        broker._append(
            context,
            "tool.input_bound",
            {
                "logical_invocation_key": context.idempotency_key,
                "step_id": context.step_id,
                "raw_input_ref": envelope.raw_input_ref,
                "execution_input_ref": envelope.execution_input_ref,
                "raw_digest": envelope.raw_digest,
                "observable_digest": envelope.observable_digest,
                "execution_digest": envelope.execution_digest,
                "mutation_count": len(envelope.mutation_chain),
                "approval_binding": envelope.approval_binding,
            },
            f"tool:{context.idempotency_key}:input-bound",
        )

    try:
        if broker.unit_of_work is not None:
            claim_status, cached, invocation_attempt = broker.unit_of_work.claim_tool_invocation(
                invocation_id=context.invocation_id,
                run_id=context.run_id,
                step_id=context.step_id,
                tool_name=name,
                tool_version=manifest.version,
                idempotency_key=context.idempotency_key,
                parameters=args,
                idempotent=manifest.idempotent,
                lease_seconds=manifest.timeout_seconds + 30,
                owner_id=context.lease_owner_id,
                fence=context.lease_fence,
                grant_id=policy_grant_id,
                grant_required=requires_grant,
            )
        else:
            claim_status, cached = broker.execution_store.claim_invocation(
                invocation_id=context.invocation_id,
                run_id=context.run_id,
                step_id=context.step_id,
                tool_name=name,
                tool_version=manifest.version,
                idempotency_key=context.idempotency_key,
                parameters=args,
                idempotent=manifest.idempotent,
                lease_seconds=manifest.timeout_seconds + 30,
                owner_id=context.lease_owner_id,
                fence=context.lease_fence,
            )
            invocation_attempt = 0
    except (ExecutionConflict, UnitOfWorkConflict) as exc:
        return broker._denied(context, "IDEMPOTENCY_CONFLICT", str(exc))
    if claim_status == InvocationStatus.COMPLETED and cached is not None:
        if not broker._cached_execution_identity_is_valid(cached, context, manifest):
            return ToolResult(
                invocation_id=cached.invocation_id,
                status=ToolStatus.ERROR,
                error_code="RECOVERY_REQUIRED",
                error_message="Completed tool invocation has no matching durable execution identity.",
            )
        return cached
    if claim_status == InvocationStatus.PENDING:
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.ERROR,
            error_code="INVOCATION_IN_PROGRESS",
            error_message="The same logical tool invocation is already running.",
        )
    if claim_status == InvocationStatus.RECOVERY_REQUIRED:
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.ERROR,
            error_code="RECOVERY_REQUIRED",
            error_message="A non-idempotent invocation has an uncertain outcome and requires operator review.",
        )
    if broker.unit_of_work is None:
        invocation_attempt = broker.execution_store.invocation_attempt(
            context.run_id,
            context.idempotency_key,
            invocation_id=context.invocation_id,
            fence=context.lease_fence,
        )
    if broker.unit_of_work is None:
        broker._append(
            context,
            "tool.started",
            {"tool": name, "version": manifest.version, "invocation_id": context.invocation_id},
            f"tool:{context.idempotency_key}:attempt:{invocation_attempt}:started",
        )
    invocation_started_at = datetime.now(UTC)
    execution_usage = None
    work_contract = None
    try:
        if (
            broker.investigation_store is not None
            and context.step_run_id is not None
            and context.run_fence > 0
            and context.step_fence > 0
        ):
            authority = broker.investigation_store.issue_authority(
                context.run_id,
                owner_id=context.lease_owner_id,
                run_fence=context.run_fence,
            )
            if context.work_contract_id is None or context.work_contract_digest is None:
                raise ToolError("Durable execution requires an AgentWorkContract")
            work_contract = broker.investigation_store.authorize_work_contract(
                context.work_contract_id,
                run_id=context.run_id,
                step_id=context.step_id,
                run_fence=context.run_fence,
                step_fence=context.step_fence,
                tool_name=name,
                content_digest=context.work_contract_digest,
            )
            permit = DispatchPermit(
                permit_id=context.dispatch_permit_id
                or str(uuid5(NAMESPACE_URL, f"permit:{context.invocation_id}:{invocation_attempt}")),
                invocation_id=context.invocation_id,
                run_id=context.run_id,
                step_run_id=context.step_run_id,
                run_fence=context.run_fence,
                step_fence=context.step_fence,
                input_digest=envelope.execution_digest,
                policy_decision_id=policy_grant_id or f"policy:{manifest_digest(manifest)}",
                approval_resolution_id=approval_request_id,
                expires_at=datetime.now(UTC) + timedelta(seconds=manifest.timeout_seconds + 30),
                nonce=str(uuid5(NAMESPACE_URL, f"permit-nonce:{context.invocation_id}:{invocation_attempt}")),
            )
            broker.investigation_store.issue_dispatch_permit(permit, authority)
            broker.investigation_store.consume_dispatch_permit(
                permit.permit_id,
                invocation_id=context.invocation_id,
                input_digest=envelope.execution_digest,
                run_fence=context.run_fence,
                step_fence=context.step_fence,
            )
        execution_usage = tool_usage(context, invocation_attempt, work_contract)
        broker._append(
            context,
            "tool.invoked",
            {"tool": name, "version": manifest.version, "skill_usage": execution_usage},
            f"tool-usage:{execution_usage['usage_id']}:invoked",
        )
        result = await tool.invoke(args, context)
        if result.invocation_id is not None and not hmac.compare_digest(
            result.invocation_id,
            context.invocation_id,
        ):
            raise ToolInvocationIdentityError("tool returned an invocation identity for another call")
        result = result.model_copy(update={"invocation_id": context.invocation_id})
        if result.status == ToolStatus.SUCCESS:
            broker.registry.validate_output(name, result.data)
        if broker.artifact_store is not None:
            # Validate and classify runner artifacts before applying the public
            # scrubber.  The typed sanitizer below restores only those refs
            # after a second CAS read; arbitrary result fields remain scrubbed.
            result = broker._persist_result_artifacts(result, context)
        result = _sanitize_tool_result(result, artifact_store=broker.artifact_store)
    except Exception as exc:
        safe_error = scrub_text(str(exc))
        failure_payload = {
            "tool": name,
            "invocation_id": context.invocation_id,
            "error": safe_error,
            "skill_usage": execution_usage,
        }
        if broker.coordinator is not None:
            broker.coordinator.fail_tool_invocation(
                run_id=context.run_id,
                idempotency_key=context.idempotency_key,
                invocation_id=context.invocation_id,
                attempt=invocation_attempt,
                owner_id=context.lease_owner_id,
                fence=context.lease_fence,
                error=safe_error,
                transition_id=f"tool:{context.idempotency_key}:attempt:{invocation_attempt}:failed",
                event_type="tool.failed",
                payload=failure_payload,
            )
        else:
            broker.execution_store.fail_invocation(
                context.run_id,
                context.idempotency_key,
                safe_error,
                invocation_id=context.invocation_id,
                attempt=invocation_attempt,
                fence=context.lease_fence,
            )
            broker._append(
                context,
                "tool.failed",
                failure_payload,
                f"tool:{context.idempotency_key}:attempt:{invocation_attempt}:failed",
            )
        return ToolResult(
            invocation_id=context.invocation_id,
            status=ToolStatus.ERROR,
            error_code=(
                "TOOL_INVOCATION_MISMATCH" if isinstance(exc, ToolInvocationIdentityError) else "TOOL_EXECUTION_FAILED"
            ),
            error_message=safe_error,
        )
    completion_payload = {
        "tool": name,
        "version": manifest.version,
        "invocation_id": context.invocation_id,
        "status": result.status.value,
        "skill_usage": execution_usage,
    }
    # Identity is committed before COMPLETED becomes visible.  A crash may
    # leave an idempotent invocation retryable, but can no longer expose a
    # completed result without immutable execution provenance.
    broker._record_execution_identity(
        result=result,
        context=context,
        manifest=manifest,
        invocation_attempt=invocation_attempt,
        envelope=envelope,
        invocation_started_at=invocation_started_at,
    )
    if broker.coordinator is not None:
        broker.coordinator.complete_tool_invocation(
            run_id=context.run_id,
            idempotency_key=context.idempotency_key,
            invocation_id=context.invocation_id,
            attempt=invocation_attempt,
            owner_id=context.lease_owner_id,
            fence=context.lease_fence,
            result=result,
            transition_id=f"tool:{context.idempotency_key}:attempt:{invocation_attempt}:completed",
            event_type="tool.completed",
            payload=completion_payload,
        )
    else:
        broker.execution_store.complete_invocation(
            context.run_id,
            context.idempotency_key,
            result,
            invocation_id=context.invocation_id,
            attempt=invocation_attempt,
            fence=context.lease_fence,
        )
        broker._append(
            context,
            "tool.completed",
            completion_payload,
            f"tool:{context.idempotency_key}:attempt:{invocation_attempt}:completed",
        )
    TOOL_CALLS.labels(tool=name, status=result.status.value).inc()
    return result
