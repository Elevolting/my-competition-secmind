from __future__ import annotations

import json
import re
from dataclasses import dataclass

from secmind.prompting.catalog import PromptCatalog
from secmind.prompting.contracts import PromptRole, PromptSeed

_WORD = re.compile(r"[A-Za-z0-9_]+")
_NUMBERED_STEP = re.compile(r"(?m)^\d+\.\s+\S")
_FIRST_LEVEL_HEADING = re.compile(r"(?m)^#\s+\S")
_COUNTEREVIDENCE_HEADING = re.compile(r"(?m)^## Counterevidence and (?:False Positives|Failure Handling)$")
_PROCEDURE_HEADINGS = (
    "## Analysis Procedure",
    "## Repair Procedure",
    "## Adaptation Procedure",
)
_COMMON_HEADINGS = (
    "## Strategy Intent",
    "## Apply This Strategy When",
    "## Do Not Use It To",
    "## Confidence and Stopping Rules",
    "## Output Discipline",
)
_PROHIBITED_CONTROL_PATTERNS = {
    "instruction_override": re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.IGNORECASE),
    "hidden_reasoning_request": re.compile(r"(?:chain[- ]of[- ]thought|hidden reasoning)", re.IGNORECASE),
    "authorization_bypass": re.compile(r"(?:pre[- ]authorized|all tasks are authorized)", re.IGNORECASE),
    "forced_positive_verdict": re.compile(
        r"(?:must find|always (?:report|classify)).{0,40}(?:vulnerability|vulnerable)",
        re.IGNORECASE,
    ),
}
_ROUTE_FIELDS = (
    "role",
    "scenario",
    "languages",
    "frameworks",
    "target_cwes",
    "evidence_gap_types",
    "phases",
    "capability_profiles",
    "repository_shapes",
    "complexity_classes",
    "risk_classes",
    "conflict_types",
    "tool_signal_types",
    "min_language_count",
    "max_language_count",
    "min_token_budget",
    "max_token_budget",
    "required_context_fields",
    "incompatible_conditions",
    "token_budget_class",
    "output_schema_ref",
)


@dataclass(frozen=True, slots=True)
class PromptQualityIssue:
    template_id: str
    code: str
    message: str


def _issue(seed: PromptSeed, code: str, message: str) -> PromptQualityIssue:
    return PromptQualityIssue(template_id=seed.template_id, code=code, message=message)


def review_seed(seed: PromptSeed) -> tuple[PromptQualityIssue, ...]:
    """Apply deterministic authoring checks before a prompt can enter shadow evaluation."""

    body = (seed.strategy_body or "").strip()
    issues: list[PromptQualityIssue] = []
    if not body:
        return (_issue(seed, "missing_content", "strategy content is required for quality review"),)

    word_count = len(_WORD.findall(body))
    if word_count < 180:
        issues.append(_issue(seed, "content_too_short", f"strategy has only {word_count} words"))
    if word_count > 700:
        issues.append(_issue(seed, "content_too_long", f"strategy has {word_count} words"))
    if len(_FIRST_LEVEL_HEADING.findall(body)) != 1:
        issues.append(_issue(seed, "invalid_title_count", "strategy must have exactly one level-one title"))

    for heading in _COMMON_HEADINGS:
        if heading not in body:
            issues.append(_issue(seed, "missing_heading", f"required heading is absent: {heading}"))
    if not any(heading in body for heading in _PROCEDURE_HEADINGS):
        issues.append(_issue(seed, "missing_procedure", "an analysis, repair, or adaptation procedure is required"))
    if seed.role == PromptRole.REPAIR:
        if "## Preservation Standard" not in body:
            issues.append(_issue(seed, "missing_preservation_standard", "repair prompts must preserve valid state"))
    elif "## Evidence Standard" not in body:
        issues.append(_issue(seed, "missing_evidence_standard", "decision prompts require an evidence standard"))
    if not _COUNTEREVIDENCE_HEADING.search(body):
        issues.append(_issue(seed, "missing_counterevidence", "counterevidence or failure handling is required"))
    if len(_NUMBERED_STEP.findall(body)) < 5:
        issues.append(_issue(seed, "procedure_too_shallow", "procedure must contain at least five ordered steps"))

    folded = body.casefold()
    for code, pattern in _PROHIBITED_CONTROL_PATTERNS.items():
        if pattern.search(body):
            issues.append(_issue(seed, code, "strategy contains prohibited control or reasoning language"))
    if re.search(r"\b(?:todo|tbd)\b|lorem ipsum", folded):
        issues.append(_issue(seed, "unfinished_content", "strategy contains an unfinished-content marker"))

    required_terms = {
        PromptRole.PLANNER: ("plan", "evidence", "success"),
        PromptRole.PRIMARY: ("vulnerable", "not_vulnerable", "inconclusive", "evidence"),
        PromptRole.CRITIC: ("vulnerable", "not_vulnerable", "inconclusive", "evidence"),
        PromptRole.REPAIR: ("promptplan", "preserv"),
    }[seed.role]
    for term in required_terms:
        if term not in folded:
            issues.append(_issue(seed, "missing_role_term", f"role-defining term is absent: {term}"))
    return tuple(issues)


def review_catalog(catalog: PromptCatalog) -> tuple[PromptQualityIssue, ...]:
    """Review every strategy and reject accidental duplicate assets or references."""

    issues: list[PromptQualityIssue] = []
    bodies: dict[str, str] = {}
    shingles: dict[str, set[tuple[str, ...]]] = {}
    references: dict[str, str] = {}
    routes: dict[str, str] = {}
    for seed in catalog.seeds():
        issues.extend(review_seed(seed))
        normalized = " ".join((seed.strategy_body or "").casefold().split())
        if normalized in bodies:
            issues.append(_issue(seed, "duplicate_content", f"strategy duplicates content from {bodies[normalized]}"))
        else:
            bodies[normalized] = seed.template_id
        words = _WORD.findall(normalized)
        current_shingles = {tuple(words[index : index + 5]) for index in range(max(0, len(words) - 4))}
        for other_id, other_shingles in shingles.items():
            union = current_shingles | other_shingles
            similarity = len(current_shingles & other_shingles) / len(union) if union else 1.0
            if similarity >= 0.55:
                issues.append(
                    _issue(
                        seed,
                        "near_duplicate_content",
                        f"strategy is too similar to {other_id} ({similarity:.3f})",
                    )
                )
        shingles[seed.template_id] = current_shingles
        if seed.strategy_ref in references:
            issues.append(
                _issue(
                    seed,
                    "duplicate_reference",
                    f"strategy reference is also used by {references[seed.strategy_ref]}",
                )
            )
        else:
            references[seed.strategy_ref] = seed.template_id
        serialized = seed.model_dump(mode="json")
        route = json.dumps(
            {field: serialized[field] for field in _ROUTE_FIELDS},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if route in routes:
            issues.append(_issue(seed, "duplicate_route", f"strategy route is indistinguishable from {routes[route]}"))
        else:
            routes[route] = seed.template_id
    return tuple(issues)


__all__ = ["PromptQualityIssue", "review_catalog", "review_seed"]
