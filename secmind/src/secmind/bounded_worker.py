from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from secmind.agent_profiles import AgentProfileRegistry
from secmind.context_manager import ContextInvariantError, MaterializedContext
from secmind.dependency_resolver import (
    DependencyResolutionError,
    DependencyResolver,
    ResolvedDependency,
)
from secmind.schemas import (
    AgentProfile,
    ContextBudget,
    Finding,
    RiskLevel,
    StepPatch,
    StepStatus,
    ToolContext,
    ToolManifest,
    ToolResult,
    ToolStatus,
    WorkItem,
)
from secmind.tools import ToolBroker, ToolError


class WorkerLoopError(ValueError):
    pass


class VerificationAction(StrEnum):
    ACCEPT = "accept"
    RETRY = "retry"
    MISSING_CONTEXT = "missing_context"
    APPROVAL_REQUIRED = "approval_required"
    TERMINAL = "terminal"
    RECOVERY_REQUIRED = "recovery_required"


class WorkerVerification:
    def __init__(self, action: VerificationAction, error_code: str | None, reason: str) -> None:
        self.action = action
        self.error_code = error_code
        self.reason = reason


class WorkerContextProvider(Protocol):
    def materialize(self, pack_id: str) -> MaterializedContext: ...

    def request_context(self, item: WorkItem, current_pack_id: str, reason: str) -> str | None: ...


class ArgumentRefiner(Protocol):
    def refine(
        self,
        item: WorkItem,
        arguments: Mapping[str, Any],
        observation: ToolResult,
        turn: int,
        context: MaterializedContext,
    ) -> dict[str, Any]: ...


class IdentityArgumentRefiner:
    def refine(
        self,
        item: WorkItem,
        arguments: Mapping[str, Any],
        observation: ToolResult,
        turn: int,
        context: MaterializedContext,
    ) -> dict[str, Any]:
        del item, observation, turn, context
        return dict(arguments)


class RetryClassifier:
    RETRYABLE_CODES = {
        "DOCKER_UNAVAILABLE",
        "EXTERNAL_TOOL_FAILED",
        "INVOCATION_IN_PROGRESS",
        "RATE_LIMITED",
        "RUNNER_BUSY",
        "SANDBOX_RUNNER_UNAVAILABLE",
        "SANDBOX_TIMEOUT",
        "TOOL_BUSY",
        "TOOL_EXECUTION_FAILED",
        "TOOL_TIMEOUT",
        "TOOL_UNAVAILABLE",
        "TRANSIENT",
    }
    RECOVERY_CODES = {"RECOVERY_REQUIRED", "UNCERTAIN_OUTCOME"}
    CONTEXT_CODES = {"CONTEXT_REQUIRED", "DEPENDENCY_CONTEXT_REQUIRED", "MISSING_CONTEXT"}
    APPROVAL_CODES = {"APPROVAL_REQUIRED"}

    def classify(self, result: ToolResult, manifest: ToolManifest) -> WorkerVerification:
        code = (result.error_code or "").upper() or None
        if result.status == ToolStatus.SUCCESS:
            return WorkerVerification(VerificationAction.ACCEPT, None, "Tool output is schema-valid.")
        if code in self.CONTEXT_CODES:
            return WorkerVerification(VerificationAction.MISSING_CONTEXT, code, "Worker requires one context refresh.")
        if code in self.APPROVAL_CODES:
            return WorkerVerification(VerificationAction.APPROVAL_REQUIRED, code, "Tool execution needs approval.")
        if code in self.RECOVERY_CODES:
            return WorkerVerification(
                VerificationAction.RECOVERY_REQUIRED,
                code,
                "Tool outcome is uncertain and cannot be retried automatically.",
            )
        retryable = result.status == ToolStatus.TIMEOUT or code in self.RETRYABLE_CODES
        if retryable and manifest.idempotent:
            return WorkerVerification(VerificationAction.RETRY, code or "TOOL_TIMEOUT", "Typed failure is retryable.")
        if retryable:
            return WorkerVerification(
                VerificationAction.RECOVERY_REQUIRED,
                "RECOVERY_REQUIRED",
                "Non-idempotent tool failure requires recovery review.",
            )
        return WorkerVerification(
            VerificationAction.TERMINAL,
            code or "TOOL_TERMINAL_FAILURE",
            result.error_message or "Tool failed with a terminal result.",
        )


class BoundedWorker:
    """Profile-constrained gather/act/verify loop with ToolBroker as its only action boundary."""

    def __init__(
        self,
        *,
        broker: ToolBroker,
        profile_registry: AgentProfileRegistry,
        context_provider: WorkerContextProvider,
        dependency_resolver: DependencyResolver | None = None,
        retry_classifier: RetryClassifier | None = None,
        argument_refiner: ArgumentRefiner | None = None,
    ) -> None:
        self.broker = broker
        self.profile_registry = profile_registry
        self.context_provider = context_provider
        self.dependency_resolver = dependency_resolver
        self.retry_classifier = retry_classifier or RetryClassifier()
        self.argument_refiner = argument_refiner or IdentityArgumentRefiner()

    async def run(self, item: WorkItem) -> StepPatch:
        tool_calls = 0
        tool_invocation_ids: list[str] = []
        artifact_bytes = 0

        def failure(
            code: str,
            reason: str,
            *,
            context: MaterializedContext | None = None,
            observation: ToolResult | None = None,
        ) -> StepPatch:
            return self._failure(
                item,
                code,
                reason,
                context=context,
                observation=observation,
                tool_invocation_ids=tool_invocation_ids,
                actual_tool_calls=tool_calls,
                artifact_bytes=artifact_bytes,
            )

        try:
            profile = self.profile_registry.get(item.agent_profile)
        except KeyError:
            return failure("AGENT_PROFILE_UNKNOWN", "Worker profile is not registered.")
        profile_error = self._validate_profile(profile, item)
        if profile_error is not None:
            return failure(profile_error[0], profile_error[1])
        if not item.context_pack_id:
            return failure("CONTEXT_PACK_REQUIRED", "Worker requires a compiled context pack.")
        if item.step_run_id is not None and (item.work_contract_id is None or item.work_contract_digest is None):
            return failure("WORK_CONTRACT_REQUIRED", "Durable step execution requires a work contract.")
        if item.step_run_id is not None and not item.skill_ids:
            return failure("SKILL_BINDING_REQUIRED", "Durable step execution requires a signed skill binding.")
        try:
            dependencies = self._resolve_dependencies(item)
            arguments = self._bind_dependency_inputs(item.inputs, dependencies)
        except DependencyResolutionError as exc:
            return failure("DEPENDENCY_INVALID", str(exc))

        current_pack_id = item.context_pack_id
        context_requested = False
        candidate_index = 0
        candidates = list(dict.fromkeys(item.capability_candidates or [item.tool_name]))
        last_result: ToolResult | None = None
        last_verification = WorkerVerification(
            VerificationAction.TERMINAL,
            "WORKER_NOT_STARTED",
            "Worker loop did not start.",
        )
        context: MaterializedContext | None = None
        tool_call_limit = min(profile.max_tool_calls, item.max_tool_calls)

        for turn in range(1, min(profile.max_turns, 3) + 1):
            try:
                context = self.context_provider.materialize(current_pack_id)
            except (ContextInvariantError, KeyError, ValueError) as exc:
                return failure("CONTEXT_PACK_INVALID", str(exc))
            if context.token_estimate > profile.max_context_tokens:
                return failure("CONTEXT_BUDGET_EXCEEDED", "Context exceeds the worker profile budget.")
            if tool_calls >= tool_call_limit:
                return failure(
                    "WORKER_TOOL_BUDGET_EXHAUSTED",
                    "Worker item tool-call budget is exhausted.",
                    context=context,
                    observation=last_result,
                )
            if candidate_index >= len(candidates):
                return failure(
                    "CAPABILITY_FALLBACK_EXHAUSTED",
                    "No approved equivalent capability remains.",
                    context=context,
                    observation=last_result,
                )
            tool_name = candidates[candidate_index]
            try:
                manifest = self.broker.registry.get(tool_name).manifest
            except (KeyError, ToolError):
                return failure("TOOL_CANDIDATE_UNKNOWN", f"Unknown tool candidate: {tool_name}")
            if item.capability not in manifest.capability_tags:
                return failure(
                    "CAPABILITY_NOT_ALLOWED",
                    f"Tool {tool_name} does not provide {item.capability}.",
                    context=context,
                )

            invocation_key = self._invocation_key(
                item,
                turn=turn,
                tool_name=tool_name,
                context_pack_id=current_pack_id,
                arguments=arguments,
                dependencies=dependencies,
            )
            invocation_id = str(uuid5(NAMESPACE_URL, f"secmind:worker-invocation:{invocation_key}"))
            last_result = await self.broker.execute(
                tool_name,
                arguments,
                ToolContext(
                    run_id=item.run_id,
                    step_id=item.step_id,
                    workspace=item.workspace_ref,
                    allowed_paths=[item.workspace_ref],
                    invocation_id=invocation_id,
                    idempotency_key=invocation_key,
                    attempt=item.attempt,
                    lease_fence=item.lease_fence,
                    lease_owner_id=item.lease_owner_id,
                    step_run_id=item.step_run_id,
                    run_fence=item.run_fence,
                    step_fence=item.step_fence,
                    usage_reservation_id=item.usage_reservation_id,
                    dispatch_permit_id=item.dispatch_permit_id,
                    work_contract_id=item.work_contract_id,
                    work_contract_digest=item.work_contract_digest,
                ),
                autonomy_policy=item.autonomy_policy,
                approval_request_id=item.approval_request_id,
            )
            tool_calls += 1
            if last_result.invocation_id is not None and last_result.invocation_id not in tool_invocation_ids:
                tool_invocation_ids.append(last_result.invocation_id)
            artifact_bytes += sum(artifact.size_bytes for artifact in last_result.artifacts)
            last_verification = self.retry_classifier.classify(last_result, manifest)
            if last_verification.action == VerificationAction.ACCEPT:
                try:
                    findings = self._findings(last_result)
                except WorkerLoopError as exc:
                    return failure(
                        "INVALID_FINDING_OUTPUT",
                        str(exc),
                        context=context,
                        observation=last_result,
                    )
                return StepPatch(
                    step_id=item.step_id,
                    transition_id=item.transition_id,
                    attempt=item.attempt,
                    lease_fence=item.lease_fence,
                    status=StepStatus.SUCCEEDED,
                    findings=findings,
                    evidence=last_result.evidence,
                    artifact_ids=[
                        artifact.artifact_id
                        for artifact in last_result.artifacts
                        if artifact.media_type != "application/vnd.secmind.evidence+json"
                    ],
                    tool_invocation_ids=list(tool_invocation_ids),
                    actual_tool_name=tool_name,
                    actual_tool_version=manifest.version,
                    actual_tool_calls=tool_calls,
                    artifact_bytes=artifact_bytes,
                    decision_summary=f"Bounded worker accepted tool evidence after {turn} turn(s).",
                    observation=last_result,
                    context_usage=self._context_usage(profile, context),
                )
            if last_verification.action == VerificationAction.MISSING_CONTEXT:
                if context_requested:
                    return failure(
                        "CONTEXT_REQUEST_LIMIT",
                        "Worker requested missing context more than once.",
                        context=context,
                        observation=last_result,
                    )
                context_requested = True
                replacement = self.context_provider.request_context(
                    item,
                    current_pack_id,
                    last_verification.reason,
                )
                if not replacement:
                    return failure(
                        "CONTEXT_UNAVAILABLE",
                        "No additional approved context is available.",
                        context=context,
                        observation=last_result,
                    )
                current_pack_id = replacement
                continue
            if last_verification.action != VerificationAction.RETRY:
                return failure(
                    last_verification.error_code or "WORKER_TERMINAL_FAILURE",
                    last_verification.reason,
                    context=context,
                    observation=last_result,
                )

            fallback_index = self._safe_fallback_index(candidates, candidate_index, manifest, item.capability)
            if fallback_index is not None:
                candidate_index = fallback_index
            elif (last_result.error_code or "").upper() == "TOOL_UNAVAILABLE":
                return failure(
                    "CAPABILITY_FALLBACK_EXHAUSTED",
                    "Unavailable tool has no approved equivalent fallback.",
                    context=context,
                    observation=last_result,
                )
            arguments = self.argument_refiner.refine(item, arguments, last_result, turn, context)

        return failure(
            "WORKER_MAX_TURNS",
            last_verification.reason or "Worker reached its bounded turn limit.",
            context=context,
            observation=last_result,
        )

    def _resolve_dependencies(self, item: WorkItem) -> list[ResolvedDependency]:
        if not item.dependency_bindings:
            return []
        if self.dependency_resolver is None:
            raise DependencyResolutionError("dependency bindings require a configured resolver")
        return self.dependency_resolver.resolve_many(item.run_id, item.dependency_bindings)

    @staticmethod
    def _bind_dependency_inputs(
        base_arguments: dict[str, Any],
        dependencies: list[ResolvedDependency],
    ) -> dict[str, Any]:
        arguments = dict(base_arguments)
        for dependency in dependencies:
            existing = arguments.get(dependency.output_name)
            artifact_id = dependency.artifact.artifact_id
            if existing is not None and existing != artifact_id:
                raise DependencyResolutionError("dependency artifact conflicts with an explicit tool argument")
            arguments[dependency.output_name] = artifact_id
        return arguments

    @staticmethod
    def _validate_profile(profile: AgentProfile, item: WorkItem) -> tuple[str, str] | None:
        if profile.max_turns > 3 or profile.max_tool_calls > 3:
            return "AGENT_PROFILE_UNBOUNDED", "Worker profile exceeds the platform turn or tool-call limit."
        if item.capability not in profile.allowed_capabilities:
            return "CAPABILITY_NOT_ALLOWED", "Worker profile does not allow the requested capability."
        if profile.max_tool_calls < 1:
            return "PROFILE_TOOL_FORBIDDEN", "Worker profile cannot invoke tools."
        return None

    def _safe_fallback_index(
        self,
        candidates: list[str],
        current_index: int,
        failed_manifest: ToolManifest,
        capability: str,
    ) -> int | None:
        failed_risk = max(failed_manifest.risk_level, failed_manifest.platform_risk or RiskLevel.R0)
        failed_evidence = set(failed_manifest.evidence_types)
        for index in range(current_index + 1, len(candidates)):
            try:
                candidate = self.broker.registry.get(candidates[index]).manifest
            except (KeyError, ToolError):
                continue
            candidate_risk = max(candidate.risk_level, candidate.platform_risk or RiskLevel.R0)
            if (
                capability in candidate.capability_tags
                and candidate.idempotent
                and candidate_risk <= failed_risk
                and failed_evidence.issubset(set(candidate.evidence_types))
            ):
                return index
        return None

    @staticmethod
    def _findings(result: ToolResult) -> list[Finding]:
        raw_findings = result.data.get("findings", [])
        if not isinstance(raw_findings, list):
            raise WorkerLoopError("tool findings must be an array")
        findings: list[Finding] = []
        for raw in raw_findings:
            try:
                findings.append(Finding.model_validate(raw))
            except (TypeError, ValueError) as exc:
                raise WorkerLoopError("tool returned a malformed normalized finding") from exc
        return findings

    @staticmethod
    def _context_usage(profile: AgentProfile, context: MaterializedContext) -> ContextBudget:
        return ContextBudget(
            total_tokens=profile.max_context_tokens,
            policy_tokens=0,
            task_tokens=0,
            skill_tool_tokens=0,
            repository_tokens=0,
            evidence_tokens=0,
            working_output_tokens=0,
            used_tokens=context.token_estimate,
        )

    @staticmethod
    def _invocation_key(
        item: WorkItem,
        *,
        turn: int,
        tool_name: str,
        context_pack_id: str,
        arguments: dict[str, Any],
        dependencies: list[ResolvedDependency],
    ) -> str:
        payload = {
            "run_id": item.run_id,
            "step_id": item.step_id,
            "attempt": item.attempt,
            "turn": turn,
            "tool": tool_name,
            "skill_ids": sorted(item.skill_ids),
            "knowledge_refs": sorted(item.knowledge_refs),
            "signed_skill_refs": sorted(item.signed_skill_refs),
            "context_pack_id": context_pack_id,
            "context_pack_digest": item.context_pack_digest,
            "context_influence_digest": item.context_influence_digest,
            "arguments": arguments,
            "dependencies": [item.input_digest for item in dependencies],
            "transition_id": item.transition_id,
            "lease_fence": item.lease_fence,
        }
        return hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _failure(
        item: WorkItem,
        code: str,
        reason: str,
        *,
        context: MaterializedContext | None = None,
        observation: ToolResult | None = None,
        tool_invocation_ids: list[str] | None = None,
        actual_tool_calls: int = 0,
        artifact_bytes: int = 0,
    ) -> StepPatch:
        context_usage = (
            ContextBudget(
                total_tokens=max(256, context.token_estimate),
                policy_tokens=0,
                task_tokens=0,
                skill_tool_tokens=0,
                repository_tokens=0,
                evidence_tokens=0,
                working_output_tokens=0,
                used_tokens=context.token_estimate,
            )
            if context is not None
            else ContextBudget()
        )
        return StepPatch(
            step_id=item.step_id,
            transition_id=item.transition_id,
            attempt=item.attempt,
            lease_fence=item.lease_fence,
            status=StepStatus.FAILED,
            decision_summary=reason,
            observation=observation,
            tool_invocation_ids=list(tool_invocation_ids or []),
            actual_tool_calls=actual_tool_calls,
            artifact_bytes=artifact_bytes,
            typed_error=code,
            context_usage=context_usage,
        )
