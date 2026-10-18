from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from secmind.audit_kernel.reviewer import PrimaryReviewEnvelope
from secmind.config import Settings
from secmind.prompting import (
    InMemoryPromptStore,
    PromptCatalog,
    PromptContext,
    PromptMode,
    PromptOptimizerGainReceipt,
    PromptRole,
    PromptSeed,
    PromptSeedStatus,
    PromptService,
    PromptServiceSettings,
)
from secmind.prompting.contracts import ComplexityClass
from secmind.runtime_profile import resolve_runtime_profile


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _catalog() -> tuple[PromptCatalog, PromptSeed]:
    seed = PromptSeed(
        template_id="primary-java-reviewed-release",
        version="1.0.0",
        role=PromptRole.PRIMARY,
        status=PromptSeedStatus.APPROVED,
        languages=("java",),
        frameworks=("jdbc",),
        target_cwes=(89,),
        strategy_ref="strategies/primary-java-reviewed-release.md",
        strategy_body="Trace only the supplied JDBC source-to-sink flow and preserve uncertainty.",
        output_schema_ref="secmind://prompt-schemas/secmind.audit_kernel.reviewer.PrimaryReviewEnvelope",
        focus_module_ids=("jdbc-flow",),
    )
    return PromptCatalog(catalog_version="release-test", status="approved", seeds=(seed,)), seed


def _context(run_id: str) -> PromptContext:
    return PromptContext.create(
        run_id=run_id,
        role=PromptRole.PRIMARY,
        phase="direct_first_primary",
        languages=("java",),
        frameworks=("jdbc",),
        target_cwes=(89,),
        capability_profile="java-source-review",
        complexity_class=ComplexityClass.HIGH,
        source_count=1,
        sink_count=1,
        token_budget=4096,
        deadline_remaining_ms=30_000,
        trusted_feature_digest=_digest("features"),
        scope_digest=_digest("scope"),
        output_schema_ref="secmind://prompt-schemas/secmind.audit_kernel.reviewer.PrimaryReviewEnvelope",
    )


@pytest.mark.asyncio
async def test_authoritative_optimizer_fails_closed_to_shadow_without_paired_gain_receipt() -> None:
    catalog, seed = _catalog()
    service = PromptService(
        catalog=catalog,
        store=InMemoryPromptStore(),
        settings=PromptServiceSettings(
            mode=PromptMode.ADAPTIVE,
            optimizer_enabled=True,
            adaptive_policy_approved=True,
            optimizer_trigger_rate_limit=1,
        ),
    )

    preparation = await service.prepare(
        context=_context("run-shadow-no-gain"),
        output_model=PrimaryReviewEnvelope,
        fixed_system_prompt="fixed baseline",
        fixed_prompt_version="fixed-v1",
    )

    assert service.optimizer_authoritative is False
    assert service.optimizer_authority_reason == "positive_paired_gain_receipt_unavailable"
    assert preparation.artifact.mode == PromptMode.CATALOG
    assert preparation.artifact.lineage_reason == "optimizer_shadow_no_gain_release"
    assert preparation.shadow_artifact is not None
    assert preparation.shadow_artifact.mode == PromptMode.ADAPTIVE_SHADOW
    assert preparation.artifact.seed_digest == seed.seed_digest
    assert preparation.artifact.seed_digest_source == "catalog"
    lineage = service.lineage(preparation.artifact.run_id, preparation.artifact.artifact_id)
    assert lineage is not None
    assert lineage["seed_digest"] == seed.seed_digest
    optimizer_receipt = lineage["optimizer_receipt"]
    assert isinstance(optimizer_receipt, dict)
    assert optimizer_receipt["receipt_digest"] == preparation.artifact.optimizer_receipt_digest
    assert optimizer_receipt["candidate_templates"] == [
        {
            "template_id": seed.template_id,
            "version": seed.version,
            "seed_digest": seed.seed_digest,
        }
    ]


def test_optimizer_gain_receipt_rejects_flags_without_positive_paired_evidence() -> None:
    with pytest.raises(ValidationError, match="positive paired gain"):
        PromptOptimizerGainReceipt(
            release_id="optimizer-release-1",
            task_set_digest=_digest("tasks"),
            evaluation_report_digest=_digest("report"),
            randomized_blocks=5,
            baseline_score=80,
            candidate_score=79,
            paired_delta_ci_low=0.1,
            no_domain_regression=True,
        )


def test_prompt_optimizer_release_policy_requires_all_four_randomized_arms() -> None:
    policy = json.loads(Path("evaluation/prompt-optimizer-release-policy.json").read_text(encoding="utf-8"))

    assert policy["required_arms"] == ["fixed", "catalog", "adaptive_shadow", "adaptive"]
    assert policy["minimum_randomized_blocks"] >= 5
    assert policy["fixed_denominator"] is True
    assert policy["missing_cells_are_failures"] is True
    assert policy["production_authoritative_optimizer_enabled"] is False


def test_named_runtime_profile_has_stable_resolved_identity_and_explicit_capability_reasons() -> None:
    settings = Settings(
        runtime_profile="offline-ci",
        model_mode="offline",
        allow_live_models=False,
        prompt_mode="adaptive",
        prompt_optimizer_enabled=True,
        prompt_adaptive_policy_approved=True,
        hybrid_knowledge_enabled=True,
        hybrid_knowledge_offline_fallback_enabled=True,
        knowledge_query_vectors_path=None,
        sandbox_runner_url="",
        unsafe_development_tools=False,
    )

    first = resolve_runtime_profile(settings)
    replay = resolve_runtime_profile(settings)

    assert first == replay
    assert first.capability_profile == "offline-ci"
    assert first.resolved_config_digest == first.digest
    assert first.profile_identity.endswith(first.resolved_config_digest)
    assert first.capabilities["model.live"].status == "disabled"
    assert first.capabilities["prompt.optimizer"].status == "enabled"
    assert first.capabilities["prompt.optimizer_authoritative"].status == "disabled"
    assert first.capabilities["prompt.optimizer_authoritative"].reason == "positive_paired_gain_receipt_unavailable"
    assert first.capabilities["tools.hybrid_knowledge"].status == "degraded"
    assert first.capabilities["tools.hybrid_knowledge"].reason == "offline_keyword_fallback_only"
    assert first.capabilities["tools.sandbox_runner"].status == "disabled"
    assert first.startup_report()["profile_identity"] == first.profile_identity


def test_same_profile_name_with_behavior_drift_gets_a_different_resolved_identity() -> None:
    baseline = resolve_runtime_profile(Settings(runtime_profile="local-full", prompt_mode="fixed"))
    changed = resolve_runtime_profile(Settings(runtime_profile="local-full", prompt_mode="catalog"))

    assert baseline.capability_profile == changed.capability_profile
    assert baseline.resolved_config_digest != changed.resolved_config_digest
    assert baseline.profile_identity != changed.profile_identity
