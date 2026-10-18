from __future__ import annotations

import re
from dataclasses import dataclass

from secmind.prompting.catalog import PromptCatalog
from secmind.prompting.contracts import PromptContext, PromptPlan, PromptSelection, canonical_digest


class PromptPolicyError(ValueError):
    """An optimizer plan attempted to cross a deterministic prompt boundary."""


_FORBIDDEN_TEXT = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"system\s+prompt|target\s+scope|authorization|privileged|"
    r"subprocess|shell\s+command|curl\s+https?://|api[_ -]?key|password|secret)"
)
_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|/(?:etc|home|root|var|proc|sys|dev)/)")


@dataclass(frozen=True, slots=True)
class PromptPolicy:
    version: str = "v1"
    max_focus_questions: int = 8
    max_focus_question_chars: int = 300
    max_focus_modules: int = 12

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "version": self.version,
                "max_focus_questions": self.max_focus_questions,
                "max_focus_question_chars": self.max_focus_question_chars,
                "max_focus_modules": self.max_focus_modules,
            }
        )


class PromptPolicyGate:
    def __init__(self, catalog: PromptCatalog, policy: PromptPolicy | None = None) -> None:
        self.catalog = catalog
        self.policy = policy or PromptPolicy()

    def validate(
        self,
        plan: PromptPlan,
        *,
        context: PromptContext,
        selection: PromptSelection,
        allowed_focus_modules: frozenset[str],
    ) -> PromptPlan:
        if selection.context_digest != context.context_digest:
            raise PromptPolicyError("prompt context and selection digest do not match")
        candidate_keys = {(item.template_id, item.version) for item in selection.candidates}
        selected_key = (plan.selected_template_id, plan.selected_template_version)
        if selected_key not in candidate_keys:
            raise PromptPolicyError("optimizer selected a template outside the deterministic Top-K")
        seed = self.catalog.get(*selected_key)
        if not seed.has_strategy_content:
            raise PromptPolicyError("metadata-only prompt seed cannot be compiled for a model request")
        if plan.context_budget.total > context.token_budget:
            raise PromptPolicyError("optimizer context allocation exceeds the reserved prompt budget")
        if len(plan.focus_module_ids) > self.policy.max_focus_modules:
            raise PromptPolicyError("optimizer selected too many focus modules")
        if not set(plan.focus_module_ids).issubset(allowed_focus_modules):
            raise PromptPolicyError("optimizer selected an unknown focus module")
        if len(plan.focus_questions) > self.policy.max_focus_questions:
            raise PromptPolicyError("optimizer generated too many focus questions")
        for question in plan.focus_questions:
            if not question.strip() or len(question) > self.policy.max_focus_question_chars:
                raise PromptPolicyError("optimizer focus question violates length limits")
            if any(ord(character) < 32 and character not in "\n\t" for character in question):
                raise PromptPolicyError("optimizer focus question contains control characters")
            if _FORBIDDEN_TEXT.search(question) or _ABSOLUTE_PATH.search(question):
                raise PromptPolicyError("optimizer focus question contains prohibited control text")
        return plan


__all__ = ["PromptPolicy", "PromptPolicyError", "PromptPolicyGate"]
