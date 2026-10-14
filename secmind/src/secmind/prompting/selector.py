from __future__ import annotations

from dataclasses import asdict, dataclass

from secmind.prompting.catalog import PromptCatalog
from secmind.prompting.contracts import (
    PromptCandidate,
    PromptContext,
    PromptMode,
    PromptSeed,
    PromptSeedStatus,
    PromptSelection,
    TokenBudgetClass,
    canonical_digest,
)

_TOKEN_CLASS_LIMITS = {
    TokenBudgetClass.SMALL: 4_096,
    TokenBudgetClass.MEDIUM: 16_384,
    TokenBudgetClass.LARGE: 65_536,
}


@dataclass(frozen=True, slots=True)
class PromptSelectionPolicy:
    version: str = "v1"
    cwe_weight: float = 30
    framework_weight: float = 20
    gap_weight: float = 18
    language_weight: float = 12
    specialization_weight: float = 6
    tool_signal_weight: float = 36
    repository_shape_weight: float = 14
    conflict_weight: float = 14
    complexity_weight: float = 24
    capability_weight: float = 8
    phase_weight: float = 6
    risk_weight: float = 4
    budget_specificity_weight: float = 40
    evaluation_weight: float = 10
    stability_weight: float = 6
    cost_weight: float = 4

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class PromptSelector:
    """Pure deterministic hard filtering followed by stable weighted ranking."""

    def __init__(self, catalog: PromptCatalog, policy: PromptSelectionPolicy | None = None) -> None:
        self.catalog = catalog
        self.policy = policy or PromptSelectionPolicy()

    def select(
        self,
        context: PromptContext,
        *,
        mode: PromptMode,
        top_k: int = 3,
        allow_reviewed_authoritative: bool = False,
    ) -> PromptSelection:
        if top_k < 1 or top_k > 10:
            raise ValueError("prompt top_k must be between 1 and 10")
        ranked: list[tuple[PromptSeed, PromptCandidate]] = []
        for seed in self.catalog.seeds(role=context.role):
            if not self._eligible(
                seed,
                context,
                mode,
                allow_reviewed_authoritative=allow_reviewed_authoritative,
            ):
                continue
            score, reasons = self._score(seed, context)
            ranked.append(
                (
                    seed,
                    PromptCandidate(
                        template_id=seed.template_id,
                        version=seed.version,
                        score=score,
                        reason_codes=reasons,
                        seed_digest=seed.seed_digest,
                    ),
                )
            )
        ranked.sort(key=lambda item: (-item[1].score, item[0].template_id, item[0].version))
        candidates = tuple(item[1] for item in ranked[:top_k])
        fallback_codes = () if candidates else ("NO_SPECIALIZED_TEMPLATE",)
        return PromptSelection(
            policy_version=self.policy.version,
            policy_digest=self.policy.digest,
            context_digest=context.context_digest,
            candidates=candidates,
            fallback_codes=fallback_codes,
        )

    @staticmethod
    def _status_eligible(
        seed: PromptSeed,
        mode: PromptMode,
        *,
        allow_reviewed_authoritative: bool = False,
    ) -> bool:
        if seed.status in {PromptSeedStatus.REVOKED, PromptSeedStatus.DEPRECATED}:
            return False
        if mode in {PromptMode.CATALOG, PromptMode.ADAPTIVE}:
            return seed.status == PromptSeedStatus.APPROVED or (
                allow_reviewed_authoritative and seed.status == PromptSeedStatus.REVIEWED
            )
        if mode == PromptMode.ADAPTIVE_SHADOW:
            return seed.status in {
                PromptSeedStatus.REVIEWED,
                PromptSeedStatus.SHADOW,
                PromptSeedStatus.APPROVED,
            }
        return False

    def _eligible(
        self,
        seed: PromptSeed,
        context: PromptContext,
        mode: PromptMode,
        *,
        allow_reviewed_authoritative: bool = False,
    ) -> bool:
        if (
            not self._status_eligible(
                seed,
                mode,
                allow_reviewed_authoritative=allow_reviewed_authoritative,
            )
            or seed.scenario != context.scenario
        ):
            return False
        if seed.output_schema_ref != context.output_schema_ref:
            return False
        if seed.languages and not set(seed.languages).intersection(context.languages):
            return False
        if seed.phases and context.phase.casefold() not in seed.phases:
            return False
        if seed.capability_profiles and context.capability_profile.casefold() not in seed.capability_profiles:
            return False
        if seed.repository_shapes and context.repository_shape not in seed.repository_shapes:
            return False
        if seed.complexity_classes and context.complexity_class not in seed.complexity_classes:
            return False
        if seed.risk_classes and context.risk_class not in seed.risk_classes:
            return False
        if seed.conflict_types and (context.conflict_type or "").casefold() not in seed.conflict_types:
            return False
        if seed.tool_signal_types and not set(seed.tool_signal_types).intersection(context.tool_signal_types):
            return False
        language_count = len(set(context.languages) - {"unknown"})
        if language_count < seed.min_language_count:
            return False
        if seed.max_language_count is not None and language_count > seed.max_language_count:
            return False
        if context.token_budget < seed.min_token_budget:
            return False
        if seed.max_token_budget is not None and context.token_budget > seed.max_token_budget:
            return False
        if seed.target_cwes and not set(seed.target_cwes).intersection(context.target_cwes):
            return False
        if seed.required_context_fields and any(
            not self._field_present(context, field) for field in seed.required_context_fields
        ):
            return False
        if set(seed.incompatible_conditions).intersection(context.evidence_gap_codes):
            return False
        if context.token_budget > _TOKEN_CLASS_LIMITS[seed.token_budget_class] * 8:
            # A tiny seed cannot be used as the only strategy for an extremely
            # large context without an explicit context adapter.
            return False
        if not seed.has_strategy_content:
            # Metadata-only skeletons remain visible through preview APIs but
            # cannot silently enter a business model request.
            return mode == PromptMode.ADAPTIVE_SHADOW
        return True

    @staticmethod
    def _field_present(context: PromptContext, name: str) -> bool:
        value = getattr(context, name, None)
        if value is None:
            return False
        if isinstance(value, (str, tuple, list, dict, set)):
            return bool(value)
        return True

    def _score(self, seed: PromptSeed, context: PromptContext) -> tuple[float, tuple[str, ...]]:
        policy = self.policy
        score = 0.0
        reasons: list[str] = []
        if seed.target_cwes and set(seed.target_cwes).intersection(context.target_cwes):
            score += policy.cwe_weight
            reasons.append("target_cwe_match")
        if seed.frameworks and set(seed.frameworks).intersection(context.frameworks):
            score += policy.framework_weight
            reasons.append("framework_match")
        if seed.evidence_gap_types and set(seed.evidence_gap_types).intersection(context.evidence_gap_codes):
            score += policy.gap_weight
            reasons.append("evidence_gap_match")
        if seed.languages and set(seed.languages).intersection(context.languages):
            score += policy.language_weight
            reasons.append("language_match")
            if len(seed.languages) <= 2:
                score += policy.specialization_weight
                reasons.append("language_specialist")
        if seed.tool_signal_types and set(seed.tool_signal_types).intersection(context.tool_signal_types):
            score += policy.tool_signal_weight
            reasons.append("tool_signal_match")
        if seed.repository_shapes and context.repository_shape in seed.repository_shapes:
            score += policy.repository_shape_weight
            reasons.append("repository_shape_match")
        if seed.conflict_types and (context.conflict_type or "").casefold() in seed.conflict_types:
            score += policy.conflict_weight
            reasons.append("conflict_type_match")
        if seed.complexity_classes and context.complexity_class in seed.complexity_classes:
            score += policy.complexity_weight
            reasons.append("complexity_match")
        if seed.capability_profiles and context.capability_profile.casefold() in seed.capability_profiles:
            score += policy.capability_weight
            reasons.append("capability_match")
        if seed.phases and context.phase.casefold() in seed.phases:
            score += policy.phase_weight
            reasons.append("phase_match")
        if seed.risk_classes and context.risk_class in seed.risk_classes:
            score += policy.risk_weight
            reasons.append("risk_match")
        if seed.min_token_budget or seed.max_token_budget is not None:
            score += policy.budget_specificity_weight
            reasons.append("token_budget_match")
        score += policy.evaluation_weight * seed.evaluation_quality
        score += policy.stability_weight * seed.stability
        cost_fitness = {
            TokenBudgetClass.SMALL: 1.0 if context.token_budget <= 4_096 else 0.5,
            TokenBudgetClass.MEDIUM: 1.0 if context.token_budget <= 16_384 else 0.6,
            TokenBudgetClass.LARGE: 0.8,
        }[seed.token_budget_class]
        score += policy.cost_weight * cost_fitness
        score -= seed.risk_penalty + len(seed.known_limitations)
        if not seed.has_strategy_content:
            score -= 1_000
            reasons.append("metadata_only_shadow_seed")
        if not reasons:
            reasons.append("role_fallback")
        return round(score, 6), tuple(reasons)


__all__ = ["PromptSelectionPolicy", "PromptSelector"]
