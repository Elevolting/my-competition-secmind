"""Deterministic v0.6 planning council and plan-contract authorization.

Model-backed components may construct a :class:`PlanProposal`, but this module
never gives a model authority to approve or execute it.  The two independent
reviews and the final contract compiler always use deterministic policy.
"""

from __future__ import annotations

import heapq
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final
from uuid import NAMESPACE_URL, uuid5

from secmind.investigation.contracts import (
    PlanContract,
    PlanProposal,
    PlanReview,
    ReviewVerdict,
    SecurityIntentAnalysis,
    StrategyLevel,
    canonical_content_digest,
)
from secmind.schemas import DependencyBinding, ModelUsage, PlanStep, RiskLevel

_MAX_COUNCIL_ROUNDS: Final = 2
_CAPABILITY_ORDER: Final = ("inventory", "sast", "secret_scan", "sbom", "dependency_audit")
_DEPENDENCIES: Final = {
    "sast": ("inventory",),
    "secret_scan": ("inventory",),
    "sbom": ("inventory",),
    "dependency_audit": ("sbom",),
}
_STEP_IDS: Final = {
    "inventory": "inventory-project",
    "sast": "scan-sast",
    # This is a deterministic workflow identifier, not a credential.
    "secret_scan": "scan-redacted-secrets",  # nosec B105
    "sbom": "generate-sbom",
    "dependency_audit": "audit-dependencies",
}
_QUICK_CAPABILITIES: Final = ("inventory", "sast", "secret_scan")

DEFAULT_ROLE_CAPABILITIES: Final[dict[str, tuple[str, ...]]] = {
    "scout": ("inventory",),
    "sast_specialist": ("sast",),
    "secret_specialist": ("secret_scan",),
    "dependency_specialist": ("sbom", "dependency_audit"),
}
DEFAULT_CAPABILITY_TOOLS: Final[dict[str, tuple[str, ...]]] = {
    "inventory": ("project-inventory",),
    "sast": ("bandit", "semgrep"),
    "secret_scan": ("gitleaks",),
    "sbom": ("syft",),
    "dependency_audit": ("osv-scanner",),
}
DEFAULT_TOOL_RISKS: Final[dict[str, RiskLevel]] = {
    "project-inventory": RiskLevel.R0,
    "bandit": RiskLevel.R1,
    "semgrep": RiskLevel.R1,
    "gitleaks": RiskLevel.R1,
    "syft": RiskLevel.R1,
    "osv-scanner": RiskLevel.R1,
}


class PlanningError(ValueError):
    """Base exception for deterministic planning failures."""


class PlanValidationError(PlanningError):
    """Raised when an untrusted proposal cannot become an executable contract."""

    def __init__(self, issues: Sequence[ValidationIssue]) -> None:
        self.issues = tuple(issues)
        detail = "; ".join(f"{item.code}: {item.message}" for item in self.issues)
        super().__init__(detail or "plan validation failed")


class PlanCouncilRejected(PlanningError):
    """Raised when either reviewer rejects, or two bounded rounds do not converge."""

    def __init__(self, reason: str, *, proposals: Sequence[PlanProposal], reviews: Sequence[PlanReview]) -> None:
        self.proposals = tuple(proposals)
        self.reviews = tuple(reviews)
        super().__init__(reason)


class IssueCategory(StrEnum):
    SCOPE = "scope"
    RISK = "risk"
    EVIDENCE = "evidence"
    BUDGET = "budget"
    DEPENDENCY = "dependency"
    FALLBACK = "fallback"
    ROLE = "role"
    INTEGRITY = "integrity"


@dataclass(frozen=True, slots=True)
class PlanningBudget:
    max_steps: int = 12
    max_tool_calls: int = 12
    max_model_calls: int = 20
    max_tokens: int = 250_000
    max_cost_units: float = 5.0

    def __post_init__(self) -> None:
        if min(self.max_steps, self.max_tool_calls, self.max_model_calls, self.max_tokens) < 0:
            raise ValueError("planning budget limits cannot be negative")
        if self.max_cost_units < 0:
            raise ValueError("planning cost limit cannot be negative")


@dataclass(frozen=True, slots=True)
class BudgetEstimate:
    steps: int
    tool_calls: int
    model_calls: int
    tokens: int
    cost_units: float

    def as_contract_envelope(self, limit: PlanningBudget) -> dict[str, int | float]:
        return {
            "estimated_steps": self.steps,
            "worst_case_tool_calls": self.tool_calls,
            "worst_case_model_calls": self.model_calls,
            "worst_case_tokens": self.tokens,
            "worst_case_cost_units": self.cost_units,
            "max_steps": limit.max_steps,
            "max_tool_calls": limit.max_tool_calls,
            "max_model_calls": limit.max_model_calls,
            "max_tokens": limit.max_tokens,
            "max_cost_units": limit.max_cost_units,
        }


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    category: IssueCategory
    message: str
    step_id: str | None = None
    repairable: bool = False


@dataclass(frozen=True, slots=True)
class PlanValidationResult:
    issues: tuple[ValidationIssue, ...]
    topological_order: tuple[str, ...]
    estimate: BudgetEstimate
    effective_risks: dict[str, RiskLevel]

    @property
    def valid(self) -> bool:
        return not self.issues


@dataclass(frozen=True, slots=True)
class CouncilOutcome:
    intent: SecurityIntentAnalysis
    accepted_proposal: PlanProposal
    proposals: tuple[PlanProposal, ...]
    reviews: tuple[PlanReview, ...]
    rounds: int

    @property
    def gap_reviews(self) -> tuple[PlanReview, ...]:
        return tuple(item for item in self.reviews if item.reviewer_profile == "security-plan-critic")

    @property
    def independent_reviews(self) -> tuple[PlanReview, ...]:
        return tuple(item for item in self.reviews if item.reviewer_profile == "independent-plan-reviewer")


def _stable_id(kind: str, digest: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"secmind:v0.6:{kind}:{digest}"))


def _normalized_strings(values: Collection[str]) -> list[str]:
    return sorted({item.strip() for item in values if item.strip()}, key=lambda item: (item.casefold(), item))


def _proposal_payload(
    *,
    run_id: str,
    parent_revision_id: str | None,
    steps: Sequence[PlanStep],
    hypotheses: Sequence[str],
    assumptions: Sequence[str],
    estimated_usage: ModelUsage,
    expected_coverage: Sequence[str],
    stop_conditions: Sequence[str],
    author_profile: str,
    prompt_ref: str | None,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "parent_revision_id": parent_revision_id,
        "hypotheses": list(hypotheses),
        "proposed_steps": [item.model_dump(mode="json") for item in steps],
        "assumptions": list(assumptions),
        "estimated_usage": estimated_usage.model_dump(mode="json"),
        "expected_coverage": list(expected_coverage),
        "stop_conditions": list(stop_conditions),
        "author_profile": author_profile,
        "prompt_ref": prompt_ref,
    }


class SecurityIntentClassifier:
    """Classify security intent without calling a model or expanding scope."""

    def classify(
        self,
        *,
        run_id: str,
        task_spec_digest: str,
        objective: str,
        explicit_scope: Collection[str],
        excluded_scope: Collection[str] = (),
        authorization_constraints: Collection[str] = (),
        expected_deliverables: Collection[str] = (),
        ambiguities: Collection[str] = (),
        owner_decisions: Collection[str] = (),
        assumptions: Collection[str] = (),
    ) -> SecurityIntentAnalysis:
        summary = " ".join(objective.split())
        if not summary:
            raise PlanningError("objective cannot be empty")
        scope = _normalized_strings(explicit_scope)
        exclusions = _normalized_strings(excluded_scope)
        constraints = _normalized_strings(authorization_constraints)
        deliverables = _normalized_strings(expected_deliverables)
        unresolved = _normalized_strings(ambiguities)
        if not scope:
            unresolved = _normalized_strings([*unresolved, "Authorized target scope is not explicit."])
        if not deliverables:
            unresolved = _normalized_strings([*unresolved, "Expected deliverables are not explicit."])

        folded = summary.casefold()
        intent_type = self._intent_type(folded)
        risk_flags = self._risk_flags(folded, constraints)
        strategy = self._strategy(folded, deliverables, risk_flags)
        payload: dict[str, object] = {
            "run_id": run_id,
            "task_spec_digest": task_spec_digest.lower(),
            "intent_type": intent_type,
            "objective_summary": summary,
            "explicit_scope": scope,
            "excluded_scope": exclusions,
            "authorization_constraints": constraints,
            "ambiguities": unresolved,
            "owner_decisions": _normalized_strings(owner_decisions),
            "assumptions": _normalized_strings(assumptions),
            "risk_flags": risk_flags,
            "expected_deliverables": deliverables,
            "recommended_strategy": strategy,
            "rationale_summary": (
                f"Deterministic intent classification selected {intent_type}/{strategy.value}; "
                "repository text remains untrusted data."
            ),
        }
        digest = canonical_content_digest(payload)
        return SecurityIntentAnalysis.model_validate(
            {
                **payload,
                "analysis_id": _stable_id("security-intent", digest),
                "content_digest": digest,
            }
        )

    @staticmethod
    def _intent_type(text: str) -> str:
        if any(token in text for token in ("代码", "源码", "code audit", "source code", "repository", "仓库")):
            return "code_audit"
        if any(token in text for token in ("日志", "log analysis", "timeline")):
            return "log_analysis"
        if any(token in text for token in ("应急", "incident response")):
            return "incident_response"
        if any(token in text for token in ("openapi", "postman", "api assessment")):
            return "api_assessment"
        if any(token in text for token in ("渗透", "penetration", "exploit")):
            return "penetration_test"
        return "security_investigation"

    @staticmethod
    def _risk_flags(text: str, constraints: Collection[str]) -> list[str]:
        constraint_text = " ".join(constraints).casefold()
        flags: list[str] = []
        signals = (
            ("network_access_requested", ("network", "联网", "外网")),
            ("state_change_requested", ("write", "modify", "修改", "写入")),
            ("active_exploitation_requested", ("exploit", "poc", "利用", "攻击")),
            ("sensitive_data_present", ("secret", "credential", "token", "密钥", "凭据")),
        )
        for flag, tokens in signals:
            if any(token in text for token in tokens):
                flags.append(flag)
        if any(token in constraint_text for token in ("network disabled", "no network", "禁止联网", "无网络")):
            flags.append("network_access_prohibited")
        return flags

    @staticmethod
    def _strategy(text: str, deliverables: Sequence[str], risk_flags: Sequence[str]) -> StrategyLevel:
        if any(token in text for token in ("快速", "quick", "smoke", "预检")):
            return StrategyLevel.QUICK
        deep_signals = ("深入", "deep", "完整", "cross-file", "供应链", "critical", "high-risk")
        if any(token in text for token in deep_signals) or len(deliverables) >= 4 or risk_flags:
            return StrategyLevel.DEEP
        return StrategyLevel.BALANCED


class PlanValidator:
    """Fail-closed deterministic validation for model or offline proposals."""

    def __init__(
        self,
        *,
        role_capabilities: Mapping[str, Collection[str]] = DEFAULT_ROLE_CAPABILITIES,
        capability_tools: Mapping[str, Collection[str]] = DEFAULT_CAPABILITY_TOOLS,
        tool_risks: Mapping[str, RiskLevel] = DEFAULT_TOOL_RISKS,
        budget: PlanningBudget | None = None,
        risk_ceiling: RiskLevel = RiskLevel.R2,
        catalog_extensions: Mapping[str, str] | None = None,
    ) -> None:
        self.role_capabilities = {
            role: tuple(_normalized_strings(capabilities)) for role, capabilities in role_capabilities.items()
        }
        self.capability_tools = {
            capability: tuple(_normalized_strings(tools)) for capability, tools in capability_tools.items()
        }
        self.tool_risks = dict(tool_risks)
        self.budget = budget or PlanningBudget()
        if risk_ceiling >= RiskLevel.R3:
            raise ValueError("R3 can never be an executable planning risk ceiling")
        self.risk_ceiling = risk_ceiling
        catalog_tools = {tool for tools in self.capability_tools.values() for tool in tools}
        missing_risks = sorted(catalog_tools - set(self.tool_risks))
        if missing_risks:
            raise ValueError(f"approved tools require platform risk entries: {', '.join(missing_risks)}")
        catalog: dict[str, object] = {
            "roles": self.role_capabilities,
            "capability_tools": self.capability_tools,
            "tool_risks": {key: int(value) for key, value in sorted(self.tool_risks.items())},
            "risk_ceiling": int(risk_ceiling),
        }
        if catalog_extensions:
            catalog["extensions"] = dict(sorted(catalog_extensions.items()))
        self.catalog_digest = canonical_content_digest(catalog)

    def validate(self, proposal: PlanProposal, intent: SecurityIntentAnalysis) -> PlanValidationResult:
        issues: list[ValidationIssue] = []
        if proposal.run_id != intent.run_id:
            issues.append(self._issue("run_id_mismatch", IssueCategory.INTEGRITY, "proposal and intent run differ"))
        expected_digest = canonical_content_digest(
            _proposal_payload(
                run_id=proposal.run_id,
                parent_revision_id=proposal.parent_revision_id,
                steps=proposal.proposed_steps,
                hypotheses=proposal.hypotheses,
                assumptions=proposal.assumptions,
                estimated_usage=proposal.estimated_usage,
                expected_coverage=proposal.expected_coverage,
                stop_conditions=proposal.stop_conditions,
                author_profile=proposal.author_profile,
                prompt_ref=proposal.prompt_ref,
            )
        )
        if expected_digest != proposal.content_digest:
            issues.append(
                self._issue("proposal_digest_mismatch", IssueCategory.INTEGRITY, "proposal content digest is invalid")
            )
        if not intent.explicit_scope:
            issues.append(self._issue("scope_missing", IssueCategory.SCOPE, "authorized scope is required"))

        order, dag_issues = self._validate_dag(proposal.proposed_steps)
        issues.extend(dag_issues)
        effective_risks: dict[str, RiskLevel] = {}
        for step in proposal.proposed_steps:
            issues.extend(self._validate_step(step, intent))
            effective = self.effective_risk(step)
            effective_risks[step.step_id] = effective
            if step.risk_hint < effective:
                issues.append(
                    self._issue(
                        "risk_hint_below_platform",
                        IssueCategory.RISK,
                        f"risk hint {step.risk_hint.name} must be raised to {effective.name}",
                        step.step_id,
                        repairable=True,
                    )
                )
            if effective > self.risk_ceiling:
                issues.append(
                    self._issue(
                        "risk_ceiling_exceeded",
                        IssueCategory.RISK,
                        f"effective risk {effective.name} exceeds {self.risk_ceiling.name}",
                        step.step_id,
                    )
                )

        coverage = set(proposal.expected_coverage)
        for capability in sorted({item.capability for item in proposal.proposed_steps} - coverage):
            issues.append(
                self._issue(
                    "coverage_missing",
                    IssueCategory.EVIDENCE,
                    f"expected coverage omits capability {capability}",
                    repairable=True,
                )
            )
        estimate = self.estimate(proposal.proposed_steps)
        if (
            proposal.estimated_usage.provider_requests < estimate.model_calls
            or proposal.estimated_usage.total_tokens < estimate.tokens
            or proposal.estimated_usage.cost_units < estimate.cost_units
        ):
            issues.append(
                self._issue(
                    "proposal_usage_underestimated",
                    IssueCategory.BUDGET,
                    "proposal usage is lower than deterministic worst-case estimates",
                )
            )
        issues.extend(self._budget_issues(estimate))
        return PlanValidationResult(tuple(issues), order, estimate, effective_risks)

    def ensure_valid(self, proposal: PlanProposal, intent: SecurityIntentAnalysis) -> PlanValidationResult:
        result = self.validate(proposal, intent)
        if not result.valid:
            raise PlanValidationError(result.issues)
        return result

    def effective_risk(self, step: PlanStep) -> RiskLevel:
        return max((step.risk_hint, *(self.tool_risks.get(name, step.risk_hint) for name in step.tool_candidates)))

    def elevate_risks(self, steps: Sequence[PlanStep]) -> list[PlanStep]:
        return [step.model_copy(update={"risk_hint": self.effective_risk(step)}, deep=True) for step in steps]

    @staticmethod
    def estimate(steps: Sequence[PlanStep]) -> BudgetEstimate:
        return BudgetEstimate(
            steps=len(steps),
            tool_calls=sum(item.estimated_tool_calls * item.max_attempts for item in steps),
            model_calls=sum(item.estimated_model_calls * item.max_attempts for item in steps),
            tokens=sum(item.estimated_tokens * item.max_attempts for item in steps),
            cost_units=round(sum(item.estimated_cost_units * item.max_attempts for item in steps), 8),
        )

    def role_for(self, capability: str) -> str:
        candidates = sorted(role for role, allowed in self.role_capabilities.items() if capability in allowed)
        if not candidates:
            raise PlanningError(f"no approved role for capability {capability}")
        return candidates[0]

    def _validate_step(self, step: PlanStep, intent: SecurityIntentAnalysis) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        allowed_capabilities = self.role_capabilities.get(step.agent_role)
        if allowed_capabilities is None:
            issues.append(self._issue("unknown_role", IssueCategory.ROLE, "agent role is not approved", step.step_id))
        elif step.capability not in allowed_capabilities:
            issues.append(
                self._issue(
                    "role_capability_mismatch",
                    IssueCategory.ROLE,
                    f"role {step.agent_role} cannot use {step.capability}",
                    step.step_id,
                )
            )
        allowed_tools = self.capability_tools.get(step.capability)
        if allowed_tools is None:
            issues.append(
                self._issue("unknown_capability", IssueCategory.ROLE, "capability is not approved", step.step_id)
            )
        elif step.estimated_tool_calls and not step.tool_candidates:
            issues.append(
                self._issue(
                    "tool_candidate_missing", IssueCategory.FALLBACK, "tool candidate is required", step.step_id
                )
            )
        else:
            unknown = sorted(set(step.tool_candidates) - set(allowed_tools))
            if unknown:
                issues.append(
                    self._issue(
                        "tool_capability_mismatch",
                        IssueCategory.FALLBACK,
                        f"tools are not approved for capability: {', '.join(unknown)}",
                        step.step_id,
                    )
                )
            if len(step.tool_candidates) != len(set(step.tool_candidates)):
                issues.append(
                    self._issue(
                        "duplicate_tool_candidate",
                        IssueCategory.FALLBACK,
                        "tool candidates must be unique",
                        step.step_id,
                        repairable=True,
                    )
                )
        if not step.success_criteria:
            issues.append(
                self._issue(
                    "success_criteria_missing",
                    IssueCategory.EVIDENCE,
                    "step requires evidence-backed success criteria",
                    step.step_id,
                    repairable=True,
                )
            )
        target = step.inputs.get("target", ".")
        if not isinstance(target, str) or not self._scope_allows(target, intent.explicit_scope):
            issues.append(
                self._issue("target_out_of_scope", IssueCategory.SCOPE, "step target is outside scope", step.step_id)
            )
        return issues

    @staticmethod
    def _scope_allows(target: str, scopes: Sequence[str]) -> bool:
        normalized = target.replace("\\", "/").strip() or "."
        candidate = PurePosixPath(normalized)
        if candidate.is_absolute() or ".." in candidate.parts or any(ord(char) < 32 for char in normalized):
            return False
        for scope in scopes:
            root_text = scope.replace("\\", "/").strip() or "."
            root = PurePosixPath(root_text)
            if root.is_absolute() or ".." in root.parts:
                continue
            if root_text == "." or candidate == root or root in candidate.parents:
                return True
        return False

    @classmethod
    def _validate_dag(cls, steps: Sequence[PlanStep]) -> tuple[tuple[str, ...], list[ValidationIssue]]:
        issues: list[ValidationIssue] = []
        ids = [item.step_id for item in steps]
        unique_ids = set(ids)
        if len(ids) != len(unique_ids):
            issues.append(cls._issue("duplicate_step_id", IssueCategory.DEPENDENCY, "step ids must be unique"))
        indegree = {step_id: 0 for step_id in unique_ids}
        children: dict[str, list[str]] = {step_id: [] for step_id in unique_ids}
        for step in steps:
            for dependency in step.dependencies:
                if dependency == step.step_id:
                    issues.append(
                        cls._issue(
                            "self_dependency",
                            IssueCategory.DEPENDENCY,
                            "step cannot depend on itself",
                            step.step_id,
                        )
                    )
                elif dependency not in unique_ids:
                    issues.append(
                        cls._issue(
                            "missing_dependency",
                            IssueCategory.DEPENDENCY,
                            f"dependency {dependency} does not exist",
                            step.step_id,
                        )
                    )
                else:
                    indegree[step.step_id] += 1
                    children[dependency].append(step.step_id)
        ready = [step_id for step_id, degree in indegree.items() if degree == 0]
        heapq.heapify(ready)
        order: list[str] = []
        while ready:
            step_id = heapq.heappop(ready)
            order.append(step_id)
            for child in sorted(children[step_id]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(ready, child)
        if len(order) != len(unique_ids):
            issues.append(cls._issue("dag_cycle", IssueCategory.DEPENDENCY, "plan DAG contains a cycle"))
        return tuple(order), issues

    def _budget_issues(self, estimate: BudgetEstimate) -> list[ValidationIssue]:
        checks = (
            ("step_budget_exceeded", estimate.steps, self.budget.max_steps),
            ("tool_budget_exceeded", estimate.tool_calls, self.budget.max_tool_calls),
            ("model_budget_exceeded", estimate.model_calls, self.budget.max_model_calls),
            ("token_budget_exceeded", estimate.tokens, self.budget.max_tokens),
            ("cost_budget_exceeded", estimate.cost_units, self.budget.max_cost_units),
        )
        return [
            self._issue(code, IssueCategory.BUDGET, f"worst-case usage {actual} exceeds limit {limit}")
            for code, actual, limit in checks
            if actual > limit
        ]

    @staticmethod
    def _issue(
        code: str,
        category: IssueCategory,
        message: str,
        step_id: str | None = None,
        repairable: bool = False,
    ) -> ValidationIssue:
        return ValidationIssue(code, category, message, step_id, repairable)


class PlanCouncil:
    """Bounded proposal, gap-review, and independent-review council."""

    def __init__(self, validator: PlanValidator, *, max_rounds: int = _MAX_COUNCIL_ROUNDS) -> None:
        if not 1 <= max_rounds <= _MAX_COUNCIL_ROUNDS:
            raise ValueError("planning council is limited to one or two rounds")
        self.validator = validator
        self.max_rounds = max_rounds

    def deliberate(
        self,
        intent: SecurityIntentAnalysis,
        *,
        initial_proposal: PlanProposal | None = None,
    ) -> CouncilOutcome:
        proposal = initial_proposal or self._offline_proposal(intent)
        proposals: list[PlanProposal] = []
        reviews: list[PlanReview] = []
        for round_number in range(1, self.max_rounds + 1):
            proposals.append(proposal)
            gap_result = self.validator.validate(proposal, intent)
            independent_result = self.validator.validate(proposal.model_copy(deep=True), intent)
            gap_review = self._review(proposal, gap_result, "security-plan-critic")
            independent_review = self._review(proposal, independent_result, "independent-plan-reviewer")
            reviews.extend((gap_review, independent_review))
            if gap_review.verdict == independent_review.verdict == ReviewVerdict.APPROVE:
                return CouncilOutcome(intent, proposal, tuple(proposals), tuple(reviews), round_number)
            if ReviewVerdict.REJECT in {gap_review.verdict, independent_review.verdict}:
                raise PlanCouncilRejected(
                    "planning council rejected a non-repairable proposal",
                    proposals=proposals,
                    reviews=reviews,
                )
            if round_number == self.max_rounds:
                break
            proposal = self._repair(proposal, gap_result.issues)
        raise PlanCouncilRejected(
            "planning council did not converge within two rounds",
            proposals=proposals,
            reviews=reviews,
        )

    def proposal_from_steps(
        self,
        intent: SecurityIntentAnalysis,
        steps: Sequence[PlanStep],
        *,
        author_profile: str,
        prompt_ref: str | None = None,
        parent_revision_id: str | None = None,
        hypotheses: Sequence[str] = (),
        assumptions: Sequence[str] = (),
        stop_conditions: Sequence[str] = ("All scheduled steps reach a typed terminal state.",),
    ) -> PlanProposal:
        return self._proposal_from_steps(
            run_id=intent.run_id,
            steps=steps,
            author_profile=author_profile,
            prompt_ref=prompt_ref,
            parent_revision_id=parent_revision_id,
            hypotheses=hypotheses,
            assumptions=assumptions,
            stop_conditions=stop_conditions,
        )

    def _proposal_from_steps(
        self,
        *,
        run_id: str,
        steps: Sequence[PlanStep],
        author_profile: str,
        prompt_ref: str | None,
        parent_revision_id: str | None,
        hypotheses: Sequence[str],
        assumptions: Sequence[str],
        stop_conditions: Sequence[str],
    ) -> PlanProposal:
        copied = [item.model_copy(deep=True) for item in steps]
        estimate = self.validator.estimate(copied)
        usage = ModelUsage(
            provider_requests=estimate.model_calls, input_tokens=estimate.tokens, cost_units=estimate.cost_units
        )
        coverage = sorted({item.capability for item in copied})
        payload = _proposal_payload(
            run_id=run_id,
            parent_revision_id=parent_revision_id,
            steps=copied,
            hypotheses=_normalized_strings(hypotheses),
            assumptions=_normalized_strings(assumptions),
            estimated_usage=usage,
            expected_coverage=coverage,
            stop_conditions=_normalized_strings(stop_conditions),
            author_profile=author_profile,
            prompt_ref=prompt_ref,
        )
        digest = canonical_content_digest(payload)
        return PlanProposal.model_validate(
            {
                **payload,
                "proposal_id": _stable_id("plan-proposal", digest),
                "content_digest": digest,
            }
        )

    def _offline_proposal(self, intent: SecurityIntentAnalysis) -> PlanProposal:
        available = set(self.validator.capability_tools)
        if intent.recommended_strategy == StrategyLevel.QUICK:
            # Inventory, a language-appropriate SAST pass and the cheap
            # redacted-secret pass are the minimum useful read-only audit.
            # Dropping secret scanning merely because the operator asked for
            # a quick result made tool coverage depend on wording rather than
            # on bounded cost.
            selected = [item for item in _QUICK_CAPABILITIES if item in available]
        else:
            selected = [item for item in _CAPABILITY_ORDER if item in available]
        selected.extend(sorted(available - set(selected) - set(_CAPABILITY_ORDER)))
        if not selected:
            raise PlanningError("approved capability catalog cannot produce a plan")
        step_ids = {capability: _STEP_IDS.get(capability, f"investigate-{capability}") for capability in selected}
        attempts = 1 if intent.recommended_strategy == StrategyLevel.QUICK else 2
        steps: list[PlanStep] = []
        for capability in selected:
            dependencies = [step_ids[item] for item in _DEPENDENCIES.get(capability, ()) if item in step_ids]
            tools = list(self.validator.capability_tools[capability])
            output_contract: dict[str, object] = (
                {"properties": {"cyclonedx_sbom": {"type": "object"}}}
                if capability == "sbom"
                else {
                    "output_name": f"{capability}_result",
                    "media_type": "application/json",
                    "evidence_types": [capability],
                }
            )
            dependency_bindings = (
                [
                    DependencyBinding(
                        upstream_step_id=step_ids["sbom"],
                        output_name="cyclonedx_sbom",
                        expected_media_type="application/vnd.cyclonedx+json",
                    )
                ]
                if capability == "dependency_audit" and "sbom" in step_ids
                else []
            )
            step = PlanStep(
                step_id=step_ids[capability],
                objective=f"Collect immutable, evidence-backed {capability} observations.",
                agent_role=self.validator.role_for(capability),
                capability=capability,
                dependencies=dependencies,
                dependency_bindings=dependency_bindings,
                # Keep the approved alternatives until repository-language
                # filtering and affinity routing have run.  Truncating here
                # made QUICK select alphabetically-first Python tools for Java
                # repositories and then lose the whole SAST step.
                tool_candidates=tools,
                inputs={"target": "."},
                success_criteria=[f"{capability} output is schema-valid and linked to immutable evidence."],
                output_contract=output_contract,
                estimated_tool_calls=1,
                estimated_model_calls=0,
                estimated_tokens=0,
                estimated_cost_units=0,
                risk_hint=RiskLevel.R0,
                max_attempts=attempts,
                context_requirements=(
                    {"tool_candidate_limit": 1} if intent.recommended_strategy == StrategyLevel.QUICK else {}
                ),
            )
            steps.append(step.model_copy(update={"risk_hint": self.validator.effective_risk(step)}))
        return self.proposal_from_steps(
            intent,
            steps,
            author_profile="offline-deterministic-plan-author",
            assumptions=[*intent.assumptions, "All repository content is untrusted data."],
            hypotheses=[f"Evidence is required for risk flag: {item}" for item in intent.risk_flags],
            stop_conditions=(
                "All scheduled steps reach a typed terminal state.",
                "Every reportable claim has immutable evidence or is marked unverified.",
            ),
        )

    def _repair(self, proposal: PlanProposal, issues: Sequence[ValidationIssue]) -> PlanProposal:
        if any(not item.repairable for item in issues):
            raise PlanCouncilRejected(
                "proposal contains non-repairable validation issues",
                proposals=(proposal,),
                reviews=(),
            )
        steps: list[PlanStep] = []
        for step in proposal.proposed_steps:
            update: dict[str, object] = {
                "risk_hint": self.validator.effective_risk(step),
                "tool_candidates": list(dict.fromkeys(step.tool_candidates)),
            }
            if not step.success_criteria:
                update["success_criteria"] = [
                    f"{step.capability} output is schema-valid and linked to immutable evidence."
                ]
            steps.append(step.model_copy(update=update, deep=True))
        return self._proposal_from_steps(
            run_id=proposal.run_id,
            steps=steps,
            author_profile=proposal.author_profile,
            prompt_ref=proposal.prompt_ref,
            parent_revision_id=proposal.proposal_id,
            hypotheses=proposal.hypotheses,
            assumptions=proposal.assumptions,
            stop_conditions=proposal.stop_conditions,
        )

    @staticmethod
    def _review(proposal: PlanProposal, result: PlanValidationResult, reviewer: str) -> PlanReview:
        non_repairable = any(not item.repairable for item in result.issues)
        verdict = (
            ReviewVerdict.REJECT if non_repairable else ReviewVerdict.REVISE if result.issues else ReviewVerdict.APPROVE
        )
        grouped: dict[IssueCategory, list[str]] = {category: [] for category in IssueCategory}
        for issue in result.issues:
            location = f"[{issue.step_id}] " if issue.step_id else ""
            grouped[issue.category].append(f"{issue.code}: {location}{issue.message}")
        dependency_errors = [*grouped[IssueCategory.DEPENDENCY], *grouped[IssueCategory.ROLE]]
        dependency_errors.extend(grouped[IssueCategory.INTEGRITY])
        payload: dict[str, object] = {
            "run_id": proposal.run_id,
            "proposal_id": proposal.proposal_id,
            "verdict": verdict,
            "scope_violations": grouped[IssueCategory.SCOPE],
            "risk_gaps": grouped[IssueCategory.RISK],
            "evidence_gaps": grouped[IssueCategory.EVIDENCE],
            "budget_gaps": grouped[IssueCategory.BUDGET],
            "dependency_errors": dependency_errors,
            "fallback_gaps": grouped[IssueCategory.FALLBACK],
            "required_corrections": sorted({item.code for item in result.issues}),
            "evidence_refs": [],
            "confidence": 1.0,
            "reviewer_profile": reviewer,
        }
        digest = canonical_content_digest(payload)
        return PlanReview.model_validate(
            {
                **payload,
                "review_id": _stable_id(f"plan-review:{reviewer}", digest),
                "content_digest": digest,
            }
        )


def expand_parallel_tool_steps(steps: Sequence[PlanStep]) -> list[PlanStep]:
    """Turn independent healthy scanners into independent DAG work."""

    expanded_by_id: dict[str, list[PlanStep]] = {}
    for step in steps:
        candidates = list(dict.fromkeys(step.tool_candidates))
        if len(candidates) <= 1:
            expanded_by_id[step.step_id] = [step.model_copy(deep=True)]
            continue
        expanded: list[PlanStep] = []
        for tool_name in candidates:
            slug = re.sub(r"[^a-z0-9]+", "-", tool_name.casefold()).strip("-") or "tool"
            requirements = dict(step.context_requirements)
            requirements.update(
                {
                    "candidate_policy": "execute_all_applicable",
                    "selected_tool": tool_name,
                    "parent_step_id": step.step_id,
                }
            )
            expanded.append(
                step.model_copy(
                    update={
                        "step_id": f"{step.step_id}-{slug}",
                        "tool_candidates": [tool_name],
                        "context_requirements": requirements,
                        "max_attempts": 1,
                    },
                    deep=True,
                )
            )
        expanded_by_id[step.step_id] = expanded

    result: list[PlanStep] = []
    for original in steps:
        for step in expanded_by_id[original.step_id]:
            dependencies = [
                expanded.step_id for dependency in step.dependencies for expanded in expanded_by_id.get(dependency, [])
            ]
            bindings: list[DependencyBinding] = []
            for binding in step.dependency_bindings:
                upstream = expanded_by_id.get(binding.upstream_step_id, [])
                if len(upstream) != 1:
                    raise PlanningError(
                        f"artifact-producing dependency cannot expand to multiple tools: {binding.upstream_step_id}"
                    )
                bindings.append(binding.model_copy(update={"upstream_step_id": upstream[0].step_id}))
            result.append(
                step.model_copy(
                    update={"dependencies": dependencies, "dependency_bindings": bindings},
                    deep=True,
                )
            )
    return result


class PlanContractCompiler:
    """Compile only independently approved, deterministic proposals."""

    def __init__(self, validator: PlanValidator, *, completion_policy: str = "evidence-obligation-gate-v1") -> None:
        self.validator = validator
        self.completion_policy = completion_policy

    def compile(self, outcome: CouncilOutcome, *, revision: int = 0) -> PlanContract:
        proposal = outcome.accepted_proposal
        result = self.validator.ensure_valid(proposal, outcome.intent)
        if len(outcome.gap_reviews) != outcome.rounds or len(outcome.independent_reviews) != outcome.rounds:
            raise PlanValidationError(
                (
                    ValidationIssue(
                        "independent_review_missing",
                        IssueCategory.INTEGRITY,
                        "both review roles must approve the accepted proposal",
                    ),
                )
            )
        final_reviews = (outcome.gap_reviews[-1], outcome.independent_reviews[-1])
        if any(item.verdict != ReviewVerdict.APPROVE for item in final_reviews):
            raise PlanValidationError(
                (
                    ValidationIssue(
                        "proposal_not_approved",
                        IssueCategory.INTEGRITY,
                        "both review roles must approve the accepted proposal",
                    ),
                )
            )

        by_id = {item.step_id: item for item in proposal.proposed_steps}
        ordered = [by_id[step_id] for step_id in result.topological_order]
        scope_digest = canonical_content_digest(
            {
                "task_spec_digest": outcome.intent.task_spec_digest,
                "explicit_scope": outcome.intent.explicit_scope,
                "excluded_scope": outcome.intent.excluded_scope,
                "authorization_constraints": outcome.intent.authorization_constraints,
            }
        )
        dag_digest = canonical_content_digest({"steps": [item.model_dump(mode="json") for item in ordered]})
        tool_sets: dict[str, list[str]] = {}
        for step in ordered:
            tool_sets.setdefault(step.capability, [])
            tool_sets[step.capability].extend(step.tool_candidates)
        tool_sets = {key: sorted(set(value)) for key, value in sorted(tool_sets.items())}
        approvals = sorted(
            f"{step.step_id}:risk-r2" for step in ordered if result.effective_risks[step.step_id] == RiskLevel.R2
        )
        payload: dict[str, object] = {
            "run_id": proposal.run_id,
            "accepted_proposal_id": proposal.proposal_id,
            "revision": revision,
            "immutable_task_scope_digest": scope_digest,
            "dag_digest": dag_digest,
            "allowed_capabilities": sorted(tool_sets),
            "allowed_tool_sets": tool_sets,
            "outcome_contract_ids": sorted(
                item.outcome_contract_id for item in ordered if item.outcome_contract_id is not None
            ),
            "budget_envelope": result.estimate.as_contract_envelope(self.validator.budget),
            "approval_requirements": approvals,
            "completion_policy": self.completion_policy,
            "catalog_digest": self.validator.catalog_digest,
        }
        digest = canonical_content_digest(payload)
        return PlanContract.model_validate(
            {
                **payload,
                "contract_id": _stable_id("plan-contract", digest),
                "content_digest": digest,
            }
        )


__all__ = [
    "BudgetEstimate",
    "CouncilOutcome",
    "IssueCategory",
    "PlanContractCompiler",
    "PlanCouncil",
    "PlanCouncilRejected",
    "PlanValidationError",
    "PlanValidationResult",
    "PlanValidator",
    "PlanningBudget",
    "PlanningError",
    "SecurityIntentClassifier",
    "ValidationIssue",
    "expand_parallel_tool_steps",
]
