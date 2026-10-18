from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from secmind.prompting.catalog import PromptCatalog
from secmind.prompting.compiler import PromptCompiler
from secmind.prompting.contracts import (
    ContextBudget,
    PromptArtifact,
    PromptContext,
    PromptMode,
    PromptOptimizationAttempt,
    PromptOptimizationRequest,
    PromptOptimizerGainReceipt,
    PromptOutcome,
    PromptPlan,
    PromptPreparation,
    PromptSeed,
    PromptSelection,
)
from secmind.prompting.optimizer import PromptOptimizer
from secmind.prompting.policy import PromptPolicyError, PromptPolicyGate
from secmind.prompting.selector import PromptSelector
from secmind.prompting.store import InMemoryPromptStore, PromptStore


class PromptServiceError(RuntimeError):
    """Prompt preparation could not produce a persisted safe fallback."""


@dataclass(frozen=True, slots=True)
class PromptServiceSettings:
    mode: PromptMode = PromptMode.FIXED
    top_k: int = 3
    optimizer_enabled: bool = False
    adaptive_policy_approved: bool = False
    allow_reviewed_authoritative: bool = False
    optimizer_trigger_rate_limit: float = 0.20
    optimizer_gain_receipt: PromptOptimizerGainReceipt | None = None


class PromptService:
    """Deterministic prompt control plane between cognitive roles and the model gateway."""

    def __init__(
        self,
        *,
        catalog: PromptCatalog,
        store: PromptStore | None = None,
        selector: PromptSelector | None = None,
        compiler: PromptCompiler | None = None,
        policy_gate: PromptPolicyGate | None = None,
        optimizer: PromptOptimizer | None = None,
        settings: PromptServiceSettings | None = None,
    ) -> None:
        self.catalog = catalog
        self.store = store or InMemoryPromptStore()
        self.selector = selector or PromptSelector(catalog)
        self.compiler = compiler or PromptCompiler()
        self.policy_gate = policy_gate or PromptPolicyGate(catalog)
        self.optimizer = optimizer or PromptOptimizer()
        self.settings = settings or PromptServiceSettings()
        if self.settings.mode == PromptMode.ADAPTIVE and not self.settings.adaptive_policy_approved:
            raise PromptServiceError("adaptive prompt mode requires an explicitly approved policy release")
        self.store.sync_templates(catalog.seeds())

    @property
    def optimizer_authoritative(self) -> bool:
        """Whether reviewed paired evidence authorizes optimizer output."""

        return bool(
            self.settings.mode == PromptMode.ADAPTIVE
            and self.settings.optimizer_enabled
            and self.settings.adaptive_policy_approved
            and self.settings.optimizer_gain_receipt is not None
        )

    @property
    def optimizer_authority_reason(self) -> str:
        if not self.settings.optimizer_enabled:
            return "optimizer_disabled_by_setting"
        if self.settings.mode not in {PromptMode.ADAPTIVE, PromptMode.ADAPTIVE_SHADOW}:
            return "optimizer_disabled_by_prompt_mode"
        if self.settings.mode == PromptMode.ADAPTIVE_SHADOW:
            return "optimizer_explicit_shadow_mode"
        if not self.settings.adaptive_policy_approved:
            return "adaptive_policy_not_approved"
        if self.settings.optimizer_gain_receipt is None:
            return "positive_paired_gain_receipt_unavailable"
        return "positive_paired_gain_receipt_verified"

    async def prepare(
        self,
        *,
        context: PromptContext,
        output_model: type[BaseModel],
        fixed_system_prompt: str,
        fixed_prompt_version: str,
        objective_summary: str = "",
    ) -> PromptPreparation:
        context.assert_identity()
        mode = self.settings.mode
        if mode == PromptMode.FIXED:
            artifact = self._persist_fixed(
                context=context,
                output_model=output_model,
                system_prompt=fixed_system_prompt,
                prompt_version=fixed_prompt_version,
                lineage_reason="fixed_mode",
            )
            return PromptPreparation(artifact=artifact)

        selection = self.selector.select(
            context,
            mode=mode,
            top_k=self.settings.top_k,
            allow_reviewed_authoritative=self.settings.allow_reviewed_authoritative,
        )
        if not selection.candidates:
            artifact = self._persist_fixed(
                context=context,
                output_model=output_model,
                system_prompt=fixed_system_prompt,
                prompt_version=fixed_prompt_version,
                fallback_codes=(*selection.fallback_codes, "FIXED_BASELINE_FALLBACK"),
                lineage_reason="selection_empty_fallback",
            )
            return PromptPreparation(artifact=artifact, selection=selection)

        candidate = selection.candidates[0]
        seed = self.catalog.get(candidate.template_id, candidate.version)
        if not seed.has_strategy_content:
            artifact = self._persist_fixed(
                context=context,
                output_model=output_model,
                system_prompt=fixed_system_prompt,
                prompt_version=fixed_prompt_version,
                fallback_codes=("PROMPT_CONTENT_NOT_SUPPLIED", "FIXED_BASELINE_FALLBACK"),
                lineage_reason="strategy_unavailable_fallback",
            )
            return PromptPreparation(artifact=artifact, selection=selection)

        base_plan = self._catalog_plan(context, seed.template_id, seed.version, seed.focus_module_ids)
        authoritative_plan = base_plan
        shadow_artifact: PromptArtifact | None = None
        attempt_id: str | None = None
        optimizer_attempt: PromptOptimizationAttempt | None = None
        lineage_reason = (
            "catalog_without_optimizer"
            if mode == PromptMode.CATALOG
            else "adaptive_optimizer_disabled"
            if not self.settings.optimizer_enabled
            else "optimizer_not_required"
        )

        if mode in {PromptMode.ADAPTIVE_SHADOW, PromptMode.ADAPTIVE} and self.settings.optimizer_enabled:
            request = PromptOptimizationRequest(
                context=context,
                objective_summary=objective_summary,
                candidate_templates=selection.candidates,
                allowed_focus_modules=seed.focus_module_ids,
                selection_digest=selection.selection_digest,
            )
            should_optimize = self.optimizer.should_optimize(request)
            inside_sample = self._inside_trigger_sample(context.context_digest)
            if should_optimize and inside_sample:
                try:
                    optimized, optimizer_attempt = await self.optimizer.optimize(request)
                    self.store.put_attempt(optimizer_attempt)
                    attempt_id = optimizer_attempt.attempt_id
                    lineage_reason = (
                        "optimizer_completed"
                        if optimizer_attempt.status == "completed"
                        else f"optimizer_{optimizer_attempt.status}"
                    )
                    optimized = self.policy_gate.validate(
                        optimized,
                        context=context,
                        selection=selection,
                        allowed_focus_modules=frozenset(seed.focus_module_ids),
                    )
                    if mode == PromptMode.ADAPTIVE and self.optimizer_authoritative:
                        authoritative_plan = optimized
                    else:
                        shadow_artifact = self._compile_and_persist(
                            context=context,
                            output_model=output_model,
                            seed=seed,
                            selection=selection,
                            plan=optimized,
                            mode=PromptMode.ADAPTIVE_SHADOW,
                            optimizer_attempt_id=attempt_id,
                            optimizer_receipt_digest=optimizer_attempt.receipt_digest,
                            lineage_reason="optimizer_shadow_applied",
                        )
                        if mode == PromptMode.ADAPTIVE:
                            lineage_reason = "optimizer_shadow_no_gain_release"
                except (PromptPolicyError, ValueError, RuntimeError) as exc:
                    # Dynamic optimization is never required to preserve the
                    # catalog/fixed business path.
                    failed = self._failed_attempt(request, exc)
                    self.store.put_attempt(failed)
                    optimizer_attempt = failed
                    attempt_id = failed.attempt_id
                    lineage_reason = "optimizer_rejected" if isinstance(exc, PromptPolicyError) else "optimizer_failed"
            elif not should_optimize:
                lineage_reason = "optimizer_not_required"
            else:
                lineage_reason = "optimizer_sampled_out"

        authority_mode = (
            PromptMode.CATALOG
            if mode == PromptMode.ADAPTIVE_SHADOW or (mode == PromptMode.ADAPTIVE and not self.optimizer_authoritative)
            else mode
        )
        artifact = self._compile_and_persist(
            context=context,
            output_model=output_model,
            seed=seed,
            selection=selection,
            plan=authoritative_plan,
            mode=authority_mode,
            optimizer_attempt_id=attempt_id,
            optimizer_receipt_digest=(None if optimizer_attempt is None else optimizer_attempt.receipt_digest),
            lineage_reason=(
                "optimizer_shadow_only" if mode == PromptMode.ADAPTIVE_SHADOW and attempt_id else lineage_reason
            ),
        )
        return PromptPreparation(
            artifact=artifact,
            selection=selection,
            shadow_artifact=shadow_artifact,
            optimizer_attempt_id=attempt_id,
        )

    def preview(self, context: PromptContext, *, mode: PromptMode | None = None) -> dict[str, object]:
        context.assert_identity()
        selected_mode = mode or self.settings.mode
        selection = None
        if selected_mode != PromptMode.FIXED:
            selection = self.selector.select(context, mode=selected_mode, top_k=self.settings.top_k)
        return {
            "mode": selected_mode.value,
            "context_id": context.context_id,
            "context_digest": context.context_digest,
            "selection": None if selection is None else selection.model_dump(mode="json"),
            "catalog": self.catalog.readiness(),
            "executes_model": False,
        }

    def prepare_fixed(
        self,
        *,
        context: PromptContext,
        output_model: type[BaseModel],
        system_prompt: str,
        prompt_version: str,
        fallback_codes: tuple[str, ...] = (),
        lineage_reason: str = "fixed_mode",
    ) -> PromptArtifact:
        """Freeze a compatibility prompt without enabling adaptive routing."""

        context.assert_identity()
        return self._persist_fixed(
            context=context,
            output_model=output_model,
            system_prompt=system_prompt,
            prompt_version=prompt_version,
            fallback_codes=fallback_codes,
            lineage_reason=lineage_reason,
        )

    def artifacts(self, run_id: str) -> tuple[PromptArtifact, ...]:
        return self.store.list_artifacts(run_id)

    def artifact(self, run_id: str, artifact_id: str) -> PromptArtifact | None:
        return self.store.get_artifact(run_id, artifact_id)

    def optimizer_attempt(self, attempt_id: str) -> PromptOptimizationAttempt | None:
        return self.store.get_attempt(attempt_id)

    def lineage(self, run_id: str, artifact_id: str) -> dict[str, object] | None:
        """Reconstruct one provider-safe prompt lineage without prompt text."""

        artifact = self.artifact(run_id, artifact_id)
        if artifact is None:
            return None
        attempt = None
        if artifact.optimizer_attempt_id is not None:
            attempt = self.optimizer_attempt(artifact.optimizer_attempt_id)
            if attempt is None:
                raise PromptServiceError("prompt optimizer receipt is missing")
            if (
                artifact.optimizer_receipt_digest is not None
                and attempt.receipt_digest != artifact.optimizer_receipt_digest
            ):
                raise PromptServiceError("prompt optimizer receipt does not match its artifact")
        return {
            **artifact.lineage_receipt,
            "optimizer_receipt": (
                None
                if attempt is None
                else {
                    "attempt_id": attempt.attempt_id,
                    "receipt_digest": attempt.receipt_digest,
                    "binding_status": (
                        "verified" if artifact.optimizer_receipt_digest is not None else "legacy_unbound"
                    ),
                    "status": attempt.status,
                    "request_digest": attempt.request_digest,
                    "selection_digest": attempt.selection_digest,
                    "candidate_templates": [
                        {
                            "template_id": candidate.template_id,
                            "version": candidate.version,
                            "seed_digest": candidate.seed_digest,
                        }
                        for candidate in attempt.candidate_templates
                    ],
                    "optimizer_model_id": attempt.optimizer_model_id,
                    "optimizer_prompt_version": attempt.optimizer_prompt_version,
                    "response_hash": attempt.response_hash,
                    "logical_call_id": attempt.logical_call_id,
                    "parent_logical_call_id": attempt.parent_logical_call_id,
                    "lineage_reason": attempt.lineage_reason,
                }
            ),
        }

    def record_outcome(self, outcome: PromptOutcome) -> PromptOutcome:
        if self.store.get_artifact(outcome.run_id, outcome.artifact_id) is None:
            raise PromptServiceError("model outcome cannot precede its prompt artifact")
        return self.store.put_outcome(outcome)

    def _persist_fixed(
        self,
        *,
        context: PromptContext,
        output_model: type[BaseModel],
        system_prompt: str,
        prompt_version: str,
        fallback_codes: tuple[str, ...] = (),
        lineage_reason: str = "fixed_mode",
    ) -> PromptArtifact:
        artifact = self.compiler.compile_fixed(
            context=context,
            output_model=output_model,
            system_prompt=system_prompt,
            prompt_version=prompt_version,
            fallback_codes=fallback_codes,
            lineage_reason=lineage_reason,
        )
        return self.store.put_artifact(artifact)

    def _compile_and_persist(
        self,
        *,
        context: PromptContext,
        output_model: type[BaseModel],
        seed: PromptSeed,
        selection: PromptSelection,
        plan: PromptPlan,
        mode: PromptMode,
        optimizer_attempt_id: str | None = None,
        optimizer_receipt_digest: str | None = None,
        lineage_reason: str = "catalog_without_optimizer",
    ) -> PromptArtifact:
        artifact = self.compiler.compile_catalog(
            context=context,
            output_model=output_model,
            seed=seed,
            selection=selection,
            plan=plan,
            mode=mode,
            optimizer_attempt_id=optimizer_attempt_id,
            optimizer_receipt_digest=optimizer_receipt_digest,
            lineage_reason=lineage_reason,
        )
        return self.store.put_artifact(artifact)

    @staticmethod
    def _failed_attempt(
        request: PromptOptimizationRequest,
        error: PromptPolicyError | ValueError | RuntimeError,
    ) -> PromptOptimizationAttempt:
        policy_rejection = isinstance(error, PromptPolicyError)
        status: Literal["rejected", "failed"] = "rejected" if policy_rejection else "failed"
        return PromptOptimizationAttempt(
            attempt_id=f"prompt-opt-{status}-{request.request_digest}",
            run_id=request.context.run_id,
            context_id=request.context.context_id,
            context_digest=request.context.context_digest,
            request_digest=request.request_digest,
            selection_digest=request.effective_selection_digest,
            candidate_template_ids=tuple(item.template_id for item in request.candidate_templates),
            candidate_templates=request.candidate_templates,
            optimizer_model_id="prompt-policy-gate" if policy_rejection else "prompt-optimizer",
            optimizer_prompt_version="secmind-prompt-optimizer-1.0",
            status=status,
            typed_error=type(error).__name__,
            lineage_reason="optimizer_rejected" if policy_rejection else "optimizer_failed",
        )

    @staticmethod
    def _catalog_plan(
        context: PromptContext,
        template_id: str,
        version: str,
        focus_modules: tuple[str, ...],
    ) -> PromptPlan:
        output_tokens = min(1_024, max(256, context.token_budget // 4))
        remainder = context.token_budget - output_tokens
        source = remainder * 65 // 100
        support = remainder * 20 // 100
        evidence = remainder - source - support
        return PromptPlan(
            selected_template_id=template_id,
            selected_template_version=version,
            focus_module_ids=focus_modules,
            analysis_order=focus_modules,
            context_budget=ContextBudget(
                source_tokens=source,
                support_tokens=support,
                evidence_tokens=evidence,
                output_tokens=output_tokens,
            ),
            limitation_codes=tuple(sorted(set(context.evidence_gap_codes))),
            reason_codes=("deterministic_catalog_selection",),
            confidence=1,
        )

    def _inside_trigger_sample(self, context_digest: str) -> bool:
        rate = min(1.0, max(0.0, self.settings.optimizer_trigger_rate_limit))
        return int(context_digest[:8], 16) / 0xFFFFFFFF <= rate


__all__ = ["PromptService", "PromptServiceError", "PromptServiceSettings"]
