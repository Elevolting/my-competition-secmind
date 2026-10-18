from __future__ import annotations

from datetime import UTC, datetime

from secmind.llm import QwenGateway
from secmind.model_policy import HARD_MAX_MODEL_TIER, MODEL_CATALOG
from secmind.model_router import ModelTaskKind
from secmind.prompting.contracts import (
    ComplexityClass,
    ContextBudget,
    PromptOptimizationAttempt,
    PromptOptimizationRequest,
    PromptPlan,
    canonical_digest,
)

OPTIMIZER_PROMPT_VERSION = "secmind-prompt-optimizer-1.0"
OPTIMIZER_SYSTEM_PROMPT = (
    "You are SecMind Prompt Optimizer. Do not solve the audit task and do not inspect raw source code. Select and "
    "specialize one supplied prompt strategy using only the structured PromptContext and allowlisted modules. Never "
    "modify authorization scope, security policy, tool permissions, budgets, evidence requirements, output schema, "
    "or the immutable system kernel. Return only a schema-valid PromptPlan."
)


class PromptOptimizer:
    """Bounded optional optimizer with one result per trusted context signature."""

    def __init__(self, gateway: QwenGateway | None = None) -> None:
        self._gateway = gateway
        self._cache: dict[str, tuple[PromptPlan, PromptOptimizationAttempt]] = {}

    @staticmethod
    def should_optimize(request: PromptOptimizationRequest) -> bool:
        context = request.context
        return bool(
            context.complexity_class == ComplexityClass.HIGH
            or context.conflict_type
            or context.evidence_gap_codes
            or context.parser_coverage < 0.8
            or (request.candidate_templates and request.candidate_templates[0].score < 20)
        )

    async def optimize(
        self,
        request: PromptOptimizationRequest,
    ) -> tuple[PromptPlan, PromptOptimizationAttempt]:
        cached = self._cache.get(request.request_digest)
        if cached is not None:
            return cached
        if not request.candidate_templates:
            raise ValueError("prompt optimization requires deterministic candidates")
        if self._gateway is None or not self._gateway.policy.network_enabled:
            result = self._deterministic(request)
        else:
            result = await self._live(request)
        self._cache[request.request_digest] = result
        return result

    def _deterministic(
        self,
        request: PromptOptimizationRequest,
    ) -> tuple[PromptPlan, PromptOptimizationAttempt]:
        candidate = request.candidate_templates[0]
        budget = self._budget(request.context.token_budget)
        focus_modules = tuple(request.allowed_focus_modules[: min(3, len(request.allowed_focus_modules))])
        plan = PromptPlan(
            selected_template_id=candidate.template_id,
            selected_template_version=candidate.version,
            focus_module_ids=focus_modules,
            analysis_order=focus_modules,
            context_budget=budget,
            limitation_codes=tuple(sorted(set(request.context.evidence_gap_codes))),
            reason_codes=("deterministic_offline_plan",),
            confidence=1,
        )
        attempt = PromptOptimizationAttempt(
            attempt_id=f"prompt-opt-{request.request_digest}",
            run_id=request.context.run_id,
            context_id=request.context.context_id,
            context_digest=request.context.context_digest,
            request_digest=request.request_digest,
            selection_digest=request.effective_selection_digest,
            candidate_template_ids=tuple(item.template_id for item in request.candidate_templates),
            candidate_templates=request.candidate_templates,
            optimizer_model_id="offline-deterministic",
            optimizer_prompt_version=OPTIMIZER_PROMPT_VERSION,
            status="completed",
            prompt_plan=plan,
            response_hash=canonical_digest(plan),
            lineage_reason="optimizer_offline_deterministic",
        )
        return plan, attempt

    async def _live(
        self,
        request: PromptOptimizationRequest,
    ) -> tuple[PromptPlan, PromptOptimizationAttempt]:
        if self._gateway is None:
            raise RuntimeError("live prompt optimizer has no model gateway")
        worker_id = self._gateway.policy.worker.model_id
        model = MODEL_CATALOG.get(worker_id)
        if model is None or model.tier > HARD_MAX_MODEL_TIER:
            raise ValueError("prompt optimizer model is outside the reviewed 5.4 ceiling")
        safe_payload = request.model_dump_json(
            exclude={"context": {"run_id", "context_id"}},
            exclude_none=True,
        )
        attempt_id = f"prompt-opt-{request.request_digest}"
        output, meta = await self._gateway.structured(
            role="worker",
            task_kind=ModelTaskKind.PROMPT_OPTIMIZATION,
            system_prompt=OPTIMIZER_SYSTEM_PROMPT,
            user_prompt=safe_payload,
            output_model=PromptPlan,
            prompt_version=OPTIMIZER_PROMPT_VERSION,
            run_id=request.context.run_id,
            prompt_selection_digest=request.effective_selection_digest,
            prompt_optimizer_attempt_id=attempt_id,
            prompt_lineage_reason="optimizer_attempt",
            lineage_stage="optimizer",
        )
        attempt = PromptOptimizationAttempt(
            attempt_id=attempt_id,
            run_id=request.context.run_id,
            context_id=request.context.context_id,
            context_digest=request.context.context_digest,
            request_digest=request.request_digest,
            selection_digest=request.effective_selection_digest,
            candidate_template_ids=tuple(item.template_id for item in request.candidate_templates),
            candidate_templates=request.candidate_templates,
            optimizer_model_id=meta.model_id,
            optimizer_prompt_version=OPTIMIZER_PROMPT_VERSION,
            status="completed",
            prompt_plan=output,
            input_tokens=meta.usage.input_tokens,
            output_tokens=meta.usage.output_tokens,
            cost_units=meta.usage.cost_units,
            response_hash=meta.response_sha256,
            logical_call_id=meta.logical_call_id,
            parent_logical_call_id=meta.parent_logical_call_id or meta.logical_call_id or attempt_id,
            lineage_reason="optimizer_live",
            created_at=datetime.now(UTC),
        )
        return output, attempt

    @staticmethod
    def _budget(total: int) -> ContextBudget:
        usable = max(0, total - min(1_024, total // 4))
        source = usable * 65 // 100
        support = usable * 20 // 100
        evidence = usable - source - support
        return ContextBudget(
            source_tokens=source,
            support_tokens=support,
            evidence_tokens=evidence,
            output_tokens=total - usable,
        )


__all__ = [
    "OPTIMIZER_PROMPT_VERSION",
    "OPTIMIZER_SYSTEM_PROMPT",
    "PromptOptimizer",
]
