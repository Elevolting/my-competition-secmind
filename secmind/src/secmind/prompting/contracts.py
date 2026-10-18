from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PROMPT_SCHEMA_VERSION = "1.0"
SHA256_PATTERN = r"^[a-f0-9]{64}$"
_SAFE_ID = re.compile(r"^[a-z][a-z0-9._:-]{1,127}$")
_SAFE_LINEAGE_REASON = re.compile(r"^[a-z][a-z0-9._:-]{1,79}$")
_SAFE_LINEAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


def canonical_digest(value: BaseModel | dict[str, Any] | list[Any] | tuple[Any, ...]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class PromptContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class PromptRole(StrEnum):
    PLANNER = "planner"
    PRIMARY = "primary"
    CRITIC = "critic"
    REPAIR = "repair"


class PromptMode(StrEnum):
    FIXED = "fixed"
    CATALOG = "catalog"
    ADAPTIVE_SHADOW = "adaptive_shadow"
    ADAPTIVE = "adaptive"


class PromptSeedStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    SHADOW = "shadow"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class RepositoryShape(StrEnum):
    SINGLE = "single"
    MULTI_MODULE = "multi_module"
    MONOREPO = "monorepo"
    PARTIAL = "partial"


class ComplexityClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskClass(StrEnum):
    NORMAL = "normal"
    HIGH_IMPACT = "high_impact"


class TokenBudgetClass(StrEnum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


class PromptContext(PromptContract):
    """A trusted feature card. Raw source and tool stdout are intentionally absent."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=64)
    context_id: str = Field(min_length=1, max_length=160)
    role: PromptRole
    scenario: Literal["code_audit"] = "code_audit"
    phase: str = Field(min_length=1, max_length=80)
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    target_cwes: tuple[int, ...] = ()
    capability_profile: str = Field(default="generic", min_length=1, max_length=128)
    repository_shape: RepositoryShape = RepositoryShape.SINGLE
    evidence_gap_codes: tuple[str, ...] = ()
    conflict_type: str | None = Field(default=None, max_length=128)
    parser_coverage: float = Field(default=1.0, ge=0, le=1)
    tool_signal_types: tuple[str, ...] = ()
    source_count: int = Field(default=0, ge=0)
    sink_count: int = Field(default=0, ge=0)
    support_file_count: int = Field(default=0, ge=0)
    complexity_class: ComplexityClass = ComplexityClass.LOW
    risk_class: RiskClass = RiskClass.NORMAL
    token_budget: int = Field(default=4096, ge=256, le=2_000_000)
    deadline_remaining_ms: int = Field(default=0, ge=0)
    trusted_feature_digest: str = Field(pattern=SHA256_PATTERN)
    scope_digest: str = Field(pattern=SHA256_PATTERN)
    output_schema_ref: str = Field(min_length=1, max_length=256)

    @field_validator(
        "languages",
        "frameworks",
        "evidence_gap_codes",
        "tool_signal_types",
    )
    @classmethod
    def normalize_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({item.strip().casefold() for item in values if item.strip()}))
        if any(not _SAFE_ID.fullmatch(item.replace("/", ":")) for item in normalized):
            raise ValueError("prompt context contains an unsafe feature identifier")
        return normalized

    @field_validator("target_cwes")
    @classmethod
    def normalize_cwes(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(value < 1 or value > 100_000 for value in values):
            raise ValueError("target CWE identifiers must be positive bounded integers")
        return tuple(sorted(set(values)))

    @property
    def context_digest(self) -> str:
        # run_id/context_id are ownership fields rather than selection inputs.
        return canonical_digest(self.model_dump(mode="json", exclude={"run_id", "context_id"}))

    def assert_identity(self) -> None:
        """Reject caller-supplied identities that do not address this feature card."""

        expected = f"prompt-context-{self.context_digest}"
        if self.context_id != expected:
            raise ValueError("prompt context identity does not match its trusted features")

    @classmethod
    def create(cls, *, run_id: str, **values: Any) -> Self:
        draft = cls(run_id=run_id, context_id="pending", **values)
        context = cls.model_validate(
            {
                **draft.model_dump(mode="json"),
                "context_id": f"prompt-context-{draft.context_digest}",
            }
        )
        context.assert_identity()
        return context


class PromptSeed(PromptContract):
    schema_version: Literal["1.0"] = "1.0"
    template_id: str = Field(min_length=2, max_length=128)
    version: str = Field(max_length=180, pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
    role: PromptRole
    status: PromptSeedStatus = PromptSeedStatus.DRAFT
    scenario: Literal["code_audit"] = "code_audit"
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    cwe_families: tuple[str, ...] = ()
    target_cwes: tuple[int, ...] = ()
    evidence_gap_types: tuple[str, ...] = ()
    phases: tuple[str, ...] = ()
    capability_profiles: tuple[str, ...] = ()
    repository_shapes: tuple[RepositoryShape, ...] = ()
    complexity_classes: tuple[ComplexityClass, ...] = ()
    risk_classes: tuple[RiskClass, ...] = ()
    conflict_types: tuple[str, ...] = ()
    tool_signal_types: tuple[str, ...] = ()
    min_language_count: int = Field(default=0, ge=0, le=32)
    max_language_count: int | None = Field(default=None, ge=1, le=32)
    min_token_budget: int = Field(default=0, ge=0, le=2_000_000)
    max_token_budget: int | None = Field(default=None, ge=256, le=2_000_000)
    required_context_fields: tuple[str, ...] = ()
    incompatible_conditions: tuple[str, ...] = ()
    token_budget_class: TokenBudgetClass = TokenBudgetClass.MEDIUM
    strategy_ref: str = Field(min_length=1, max_length=300)
    strategy_body: str | None = Field(default=None, max_length=32_000)
    output_schema_ref: str = Field(min_length=1, max_length=256)
    security_kernel_ref: str = Field(default="secmind-prompt-kernel-v1", min_length=1, max_length=128)
    focus_module_ids: tuple[str, ...] = ()
    known_limitations: tuple[str, ...] = ()
    evaluation_quality: float = Field(default=0, ge=0, le=1)
    stability: float = Field(default=0, ge=0, le=1)
    risk_penalty: float = Field(default=0, ge=0, le=100)

    @field_validator(
        "languages",
        "frameworks",
        "cwe_families",
        "evidence_gap_types",
        "phases",
        "capability_profiles",
        "conflict_types",
        "tool_signal_types",
        "required_context_fields",
        "incompatible_conditions",
        "focus_module_ids",
    )
    @classmethod
    def normalize_sets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({item.strip().casefold() for item in values if item.strip()}))

    @field_validator("target_cwes")
    @classmethod
    def normalize_seed_cwes(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted(set(values)))

    @model_validator(mode="after")
    def approved_seed_has_reviewed_body(self) -> Self:
        if (
            self.status
            in {
                PromptSeedStatus.REVIEWED,
                PromptSeedStatus.SHADOW,
                PromptSeedStatus.APPROVED,
            }
            and not (self.strategy_body or "").strip()
        ):
            raise ValueError("a reviewed prompt seed requires strategy content")
        if not _SAFE_ID.fullmatch(self.template_id):
            raise ValueError("template_id must be a canonical lower-case identifier")
        if self.max_language_count is not None and self.min_language_count > self.max_language_count:
            raise ValueError("prompt seed language-count bounds are inverted")
        if self.max_token_budget is not None and self.min_token_budget > self.max_token_budget:
            raise ValueError("prompt seed token-budget bounds are inverted")
        return self

    @property
    def seed_digest(self) -> str:
        return canonical_digest(self)

    @property
    def has_strategy_content(self) -> bool:
        return bool((self.strategy_body or "").strip())


class PromptCandidate(PromptContract):
    template_id: str
    version: str = Field(min_length=1, max_length=180)
    score: float
    reason_codes: tuple[str, ...]
    seed_digest: str = Field(pattern=SHA256_PATTERN)


class PromptSelection(PromptContract):
    policy_version: str = Field(min_length=1, max_length=80)
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    context_digest: str = Field(pattern=SHA256_PATTERN)
    candidates: tuple[PromptCandidate, ...]
    fallback_codes: tuple[str, ...] = ()

    @property
    def selection_digest(self) -> str:
        return canonical_digest(self)


class ContextBudget(PromptContract):
    source_tokens: int = Field(default=0, ge=0)
    support_tokens: int = Field(default=0, ge=0)
    evidence_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return self.source_tokens + self.support_tokens + self.evidence_tokens + self.output_tokens


class PromptPlan(PromptContract):
    schema_version: Literal["1.0"] = "1.0"
    selected_template_id: str
    selected_template_version: str
    focus_module_ids: tuple[str, ...] = ()
    analysis_order: tuple[str, ...] = ()
    focus_questions: tuple[str, ...] = ()
    context_budget: ContextBudget
    limitation_codes: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    confidence: float = Field(default=1, ge=0, le=1)

    @field_validator("focus_module_ids", "analysis_order", "limitation_codes", "reason_codes")
    @classmethod
    def unique_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("prompt plan identifiers must be unique")
        return values

    @property
    def plan_digest(self) -> str:
        return canonical_digest(self)


class PromptOptimizationRequest(PromptContract):
    context: PromptContext
    objective_summary: str = Field(default="", max_length=2_000)
    candidate_templates: tuple[PromptCandidate, ...]
    allowed_focus_modules: tuple[str, ...] = ()
    allowed_patch_operations: tuple[
        Literal[
            "select_template",
            "select_focus_module",
            "order_analysis_stage",
            "allocate_context_budget",
            "add_focus_question",
            "declare_limitation",
        ],
        ...,
    ] = (
        "select_template",
        "select_focus_module",
        "order_analysis_stage",
        "allocate_context_budget",
        "add_focus_question",
        "declare_limitation",
    )
    optimizer_policy_version: str = Field(default="v1", min_length=1, max_length=80)
    # The deterministic selector owns this digest. Offline/legacy callers may
    # omit it; ``effective_selection_digest`` still gives provider attempts a
    # non-empty, metadata-only identity instead of silently losing lineage.
    selection_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @property
    def request_digest(self) -> str:
        return canonical_digest(self)

    @property
    def effective_selection_digest(self) -> str:
        if self.selection_digest is not None:
            return self.selection_digest
        return canonical_digest(
            {
                "candidate_templates": [item.model_dump(mode="json") for item in self.candidate_templates],
                "policy_version": self.optimizer_policy_version,
            }
        )


class PromptOptimizationAttempt(PromptContract):
    attempt_id: str = Field(min_length=1, max_length=160)
    run_id: str
    context_id: str
    context_digest: str = Field(pattern=SHA256_PATTERN)
    request_digest: str = Field(pattern=SHA256_PATTERN)
    selection_digest: str = Field(pattern=SHA256_PATTERN)
    candidate_template_ids: tuple[str, ...]
    candidate_templates: tuple[PromptCandidate, ...] = ()
    optimizer_model_id: str
    optimizer_prompt_version: str
    status: Literal["completed", "rejected", "failed", "skipped"]
    prompt_plan: PromptPlan | None = None
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_units: float = Field(default=0, ge=0)
    response_hash: str | None = Field(default=None, pattern=SHA256_PATTERN)
    typed_error: str | None = Field(default=None, max_length=200)
    logical_call_id: str | None = Field(default=None, max_length=128)
    parent_logical_call_id: str | None = Field(default=None, max_length=128)
    lineage_reason: str = Field(default="optimizer_attempt", min_length=2, max_length=80)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def fill_legacy_lineage(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        normalized = dict(values)
        if not normalized.get("request_digest"):
            normalized["request_digest"] = canonical_digest(
                {
                    "context_digest": normalized.get("context_digest", ""),
                    "candidate_template_ids": normalized.get("candidate_template_ids", ()),
                    "optimizer_model_id": normalized.get("optimizer_model_id", ""),
                    "optimizer_prompt_version": normalized.get("optimizer_prompt_version", ""),
                }
            )
        if not normalized.get("selection_digest"):
            normalized["selection_digest"] = canonical_digest(
                {
                    "candidate_template_ids": normalized.get("candidate_template_ids", ()),
                    "optimizer_policy": normalized.get("optimizer_prompt_version", ""),
                }
            )
        normalized.setdefault("lineage_reason", "legacy_optimizer_attempt")
        return normalized

    @model_validator(mode="after")
    def validate_identity_fields(self) -> Self:
        if not _SAFE_LINEAGE_ID.fullmatch(self.attempt_id):
            raise ValueError("prompt optimizer attempt id is not a safe lineage identity")
        if not _SAFE_LINEAGE_REASON.fullmatch(self.lineage_reason):
            raise ValueError("prompt optimizer lineage reason is not a typed identifier")
        if self.candidate_templates:
            template_ids = tuple(item.template_id for item in self.candidate_templates)
            if template_ids != self.candidate_template_ids:
                raise ValueError("optimizer candidate identities do not match their seed receipts")
            if len({(item.template_id, item.version, item.seed_digest) for item in self.candidate_templates}) != len(
                self.candidate_templates
            ):
                raise ValueError("optimizer candidate seed receipts must be unique")
        return self

    @property
    def receipt_digest(self) -> str:
        """Return the immutable optimizer receipt identity.

        ``created_at`` is deliberately excluded: retries that reconstruct the
        same logical optimization must retain one content identity.
        """

        return canonical_digest(self.model_dump(mode="json", exclude={"created_at"}))


class PromptOptimizerGainReceipt(PromptContract):
    """Reviewed paired-evaluation evidence required for optimizer authority.

    A deployment flag is not evidence.  The optimizer may affect an
    authoritative prompt only when release wiring supplies a receipt whose
    paired confidence bound is positive and whose domain regression gate
    passed.  SecMind v0.8.6 ships without such a receipt, so optimizer output
    remains shadow-only.
    """

    schema_version: Literal["1.0"] = "1.0"
    release_id: str = Field(min_length=3, max_length=160)
    task_set_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_report_digest: str = Field(pattern=SHA256_PATTERN)
    arms: tuple[
        Literal["fixed"],
        Literal["catalog"],
        Literal["adaptive_shadow"],
        Literal["adaptive"],
    ] = ("fixed", "catalog", "adaptive_shadow", "adaptive")
    randomized_blocks: int = Field(ge=5)
    fixed_denominator: Literal[True] = True
    baseline_score: float = Field(ge=0, le=100)
    candidate_score: float = Field(ge=0, le=100)
    paired_delta_ci_low: float = Field(gt=0, le=100)
    no_domain_regression: Literal[True] = True

    @model_validator(mode="after")
    def validate_positive_gain(self) -> Self:
        if self.candidate_score <= self.baseline_score:
            raise ValueError("authoritative optimizer receipt requires positive paired gain")
        if not _SAFE_LINEAGE_ID.fullmatch(self.release_id):
            raise ValueError("optimizer release id is not a safe lineage identity")
        return self

    @property
    def receipt_digest(self) -> str:
        return canonical_digest(self)


class PromptArtifact(PromptContract):
    schema_version: Literal["1.0"] = "1.0"
    artifact_id: str = Field(pattern=SHA256_PATTERN)
    run_id: str
    context_id: str
    role: PromptRole
    mode: PromptMode
    system_prompt: str = Field(min_length=1, max_length=100_000)
    user_strategy_prefix: str = Field(default="", max_length=100_000)
    preserve_fixed_user_prompt: bool = False
    template_id: str
    template_version: str = Field(min_length=1, max_length=180)
    seed_digest: str = Field(pattern=SHA256_PATTERN)
    seed_digest_source: Literal["catalog", "fixed_prompt", "legacy_synthetic"]
    focus_module_ids: tuple[str, ...] = ()
    security_kernel_digest: str = Field(pattern=SHA256_PATTERN)
    role_contract_digest: str = Field(pattern=SHA256_PATTERN)
    output_schema_digest: str = Field(pattern=SHA256_PATTERN)
    context_digest: str = Field(pattern=SHA256_PATTERN)
    selection_policy_digest: str = Field(pattern=SHA256_PATTERN)
    selection_digest: str = Field(pattern=SHA256_PATTERN)
    optimizer_attempt_id: str | None = Field(default=None, max_length=160)
    optimizer_receipt_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    lineage_reason: str = Field(min_length=2, max_length=80)
    prompt_plan_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    rendered_prompt_digest: str = Field(pattern=SHA256_PATTERN)
    estimated_input_tokens: int = Field(ge=0)
    prompt_version: str = Field(min_length=1, max_length=180)
    fallback_codes: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def fill_legacy_lineage(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        normalized = dict(values)
        selection_policy_digest = normalized.get("selection_policy_digest")
        if not normalized.get("selection_digest"):
            normalized["selection_digest"] = selection_policy_digest or canonical_digest(
                {
                    "mode": normalized.get("mode", "fixed"),
                    "template_id": normalized.get("template_id", "legacy"),
                    "template_version": normalized.get("template_version", "legacy"),
                }
            )
        if "lineage_reason" not in normalized:
            mode = str(normalized.get("mode", "fixed"))
            normalized["lineage_reason"] = "legacy_fixed" if mode.endswith("fixed") else "legacy_catalog"
        normalized.setdefault("optimizer_attempt_id", None)
        if not normalized.get("seed_digest"):
            normalized["seed_digest"] = canonical_digest(
                {
                    "legacy": True,
                    "template_id": normalized.get("template_id", "legacy"),
                    "template_version": normalized.get("template_version", "legacy"),
                    "rendered_prompt_digest": normalized.get("rendered_prompt_digest", ""),
                }
            )
            normalized["seed_digest_source"] = "legacy_synthetic"
        normalized.setdefault("seed_digest_source", "legacy_synthetic")
        normalized.setdefault("optimizer_receipt_digest", None)
        return normalized

    @model_validator(mode="after")
    def validate_lineage_fields(self) -> Self:
        if self.optimizer_attempt_id is not None and not _SAFE_LINEAGE_ID.fullmatch(self.optimizer_attempt_id):
            raise ValueError("prompt optimizer attempt id is not a safe lineage identity")
        if not _SAFE_LINEAGE_REASON.fullmatch(self.lineage_reason):
            raise ValueError("prompt lineage reason is not a typed identifier")
        if self.optimizer_receipt_digest is not None and self.optimizer_attempt_id is None:
            raise ValueError("optimizer receipt digest requires an optimizer attempt identity")
        return self

    @property
    def prompt_selection_digest(self) -> str:
        """Provider-facing alias for the immutable selector identity."""

        return self.selection_digest

    @property
    def prompt_optimizer_attempt_id(self) -> str | None:
        return self.optimizer_attempt_id

    @property
    def lineage_receipt(self) -> dict[str, Any]:
        """Return the secret-free identity needed to replay prompt selection."""

        return {
            "artifact_id": self.artifact_id,
            "run_id": self.run_id,
            "context_id": self.context_id,
            "role": self.role.value,
            "mode": self.mode.value,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "seed_digest": self.seed_digest,
            "seed_digest_source": self.seed_digest_source,
            "prompt_version": self.prompt_version,
            "selection_policy_digest": self.selection_policy_digest,
            "selection_digest": self.selection_digest,
            "optimizer_attempt_id": self.optimizer_attempt_id,
            "optimizer_receipt_digest": self.optimizer_receipt_digest,
            "lineage_reason": self.lineage_reason,
            "prompt_plan_digest": self.prompt_plan_digest,
            "rendered_prompt_digest": self.rendered_prompt_digest,
        }

    def compose_user_prompt(self, untrusted_data: str) -> str:
        if self.preserve_fixed_user_prompt:
            return untrusted_data
        parts = [self.user_strategy_prefix.strip()] if self.user_strategy_prefix.strip() else []
        parts.append(f"<UNTRUSTED_TASK_AND_EVIDENCE_DATA>\n{untrusted_data}\n</UNTRUSTED_TASK_AND_EVIDENCE_DATA>")
        return "\n\n".join(parts)


class PromptPreparation(PromptContract):
    artifact: PromptArtifact
    selection: PromptSelection | None = None
    shadow_artifact: PromptArtifact | None = None
    optimizer_attempt_id: str | None = None

    @property
    def selection_digest(self) -> str:
        return self.artifact.selection_digest

    @property
    def lineage_reason(self) -> str:
        return self.artifact.lineage_reason


class PromptOutcome(PromptContract):
    artifact_id: str = Field(pattern=SHA256_PATTERN)
    run_id: str
    model_receipt_id: str
    schema_valid: bool
    evidence_complete: bool | None = None
    verdict_status: str | None = None
    latency_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_units: float = Field(ge=0)
    shadow_arm: bool = False
    evaluation_ref: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


__all__ = [
    "PROMPT_SCHEMA_VERSION",
    "ComplexityClass",
    "ContextBudget",
    "PromptArtifact",
    "PromptCandidate",
    "PromptContext",
    "PromptMode",
    "PromptOptimizationAttempt",
    "PromptOptimizationRequest",
    "PromptOutcome",
    "PromptPlan",
    "PromptPreparation",
    "PromptRole",
    "PromptSeed",
    "PromptSeedStatus",
    "PromptSelection",
    "RepositoryShape",
    "RiskClass",
    "TokenBudgetClass",
    "canonical_digest",
]
