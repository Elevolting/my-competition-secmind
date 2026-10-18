from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from secmind.prompting.contracts import (
    ComplexityClass,
    PromptCandidate,
    PromptContext,
    PromptOptimizationRequest,
    PromptPlan,
    PromptRole,
)
from secmind.prompting.optimizer import OPTIMIZER_PROMPT_VERSION, PromptOptimizer


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _request(
    *,
    complexity: ComplexityClass = ComplexityClass.LOW,
    parser_coverage: float = 1,
    conflict_type: str | None = None,
    gaps: tuple[str, ...] = (),
    score: float = 50,
    candidates: bool = True,
    token_budget: int = 4_096,
) -> PromptOptimizationRequest:
    context = PromptContext.create(
        run_id="run-optimize",
        role=PromptRole.PRIMARY,
        phase="direct_first_primary",
        languages=("python",),
        capability_profile="code-audit",
        evidence_gap_codes=gaps,
        conflict_type=conflict_type,
        parser_coverage=parser_coverage,
        complexity_class=complexity,
        token_budget=token_budget,
        trusted_feature_digest=_digest("features"),
        scope_digest=_digest("scope"),
        output_schema_ref="secmind://prompt-schemas/primary",
    )
    candidate_items = (
        (
            PromptCandidate(
                template_id="primary-python-audit",
                version="1.2.0",
                score=score,
                reason_codes=("language_match",),
                seed_digest=_digest("seed"),
            ),
        )
        if candidates
        else ()
    )
    return PromptOptimizationRequest(
        context=context,
        objective_summary="review authentication handling",
        candidate_templates=candidate_items,
        allowed_focus_modules=("authn", "taint", "crypto", "overflow"),
    )


@pytest.mark.parametrize(
    "optimization_request",
    [
        _request(complexity=ComplexityClass.HIGH),
        _request(conflict_type="severity_conflict"),
        _request(gaps=("missing_sink",)),
        _request(parser_coverage=0.79),
        _request(score=19.99),
    ],
)
def test_optimizer_triggers_only_for_bounded_complexity_signals(
    optimization_request: PromptOptimizationRequest,
) -> None:
    assert PromptOptimizer.should_optimize(optimization_request)
    assert not PromptOptimizer.should_optimize(_request())


@pytest.mark.asyncio
async def test_offline_optimizer_is_deterministic_bounded_and_cached() -> None:
    request = _request(gaps=("z_gap", "a_gap", "z_gap"), token_budget=8_000)
    optimizer = PromptOptimizer()

    first = await optimizer.optimize(request)
    second = await optimizer.optimize(request)

    assert first is second
    plan, attempt = first
    assert plan.selected_template_id == "primary-python-audit"
    assert plan.focus_module_ids == ("authn", "taint", "crypto")
    assert plan.analysis_order == plan.focus_module_ids
    assert plan.limitation_codes == ("a_gap", "z_gap")
    assert plan.context_budget.total == 8_000
    assert plan.context_budget.output_tokens == 1_024
    assert attempt.status == "completed"
    assert attempt.prompt_plan == plan
    assert attempt.optimizer_model_id == "offline-deterministic"
    assert attempt.response_hash == plan.plan_digest
    assert attempt.request_digest == request.request_digest
    assert attempt.selection_digest == request.effective_selection_digest
    assert attempt.lineage_reason == "optimizer_offline_deterministic"


@pytest.mark.asyncio
async def test_optimizer_rejects_an_empty_deterministic_candidate_set() -> None:
    with pytest.raises(ValueError, match="deterministic candidates"):
        await PromptOptimizer().optimize(_request(candidates=False))


def test_optimizer_budget_reserves_a_quarter_for_small_contexts() -> None:
    budget = PromptOptimizer._budget(256)
    assert budget.output_tokens == 64
    assert budget.total == 256
    assert budget.source_tokens == 124
    assert budget.support_tokens == 38
    assert budget.evidence_tokens == 30


@pytest.mark.asyncio
async def test_live_optimizer_uses_worker_model_and_redacts_context_ownership() -> None:
    request = _request(complexity=ComplexityClass.HIGH)
    expected = PromptPlan(
        selected_template_id="primary-python-audit",
        selected_template_version="1.2.0",
        focus_module_ids=("taint",),
        analysis_order=("taint",),
        context_budget=PromptOptimizer._budget(request.context.token_budget),
        reason_codes=("model_selected",),
        confidence=0.8,
    )

    class Gateway:
        policy = SimpleNamespace(network_enabled=True, worker=SimpleNamespace(model_id="qwen-plus"))

        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        async def structured(self, **kwargs: Any):
            self.calls.append(kwargs)
            assert request.context.run_id not in kwargs["user_prompt"]
            assert request.context.context_id not in kwargs["user_prompt"]
            assert kwargs["run_id"] == request.context.run_id
            assert kwargs["prompt_version"] == OPTIMIZER_PROMPT_VERSION
            assert kwargs["prompt_selection_digest"] == request.effective_selection_digest
            assert kwargs["prompt_optimizer_attempt_id"] == f"prompt-opt-{request.request_digest}"
            assert kwargs["prompt_lineage_reason"] == "optimizer_attempt"
            assert kwargs["lineage_stage"] == "optimizer"
            meta = SimpleNamespace(
                model_id="qwen-plus",
                usage=SimpleNamespace(input_tokens=123, output_tokens=45, cost_units=0.25),
                response_sha256=_digest("response"),
                logical_call_id="logical-call-live",
                parent_logical_call_id=None,
            )
            return expected, meta

    gateway = Gateway()
    plan, attempt = await PromptOptimizer(gateway).optimize(request)  # type: ignore[arg-type]
    assert plan == expected
    assert len(gateway.calls) == 1
    assert attempt.input_tokens == 123
    assert attempt.output_tokens == 45
    assert attempt.cost_units == 0.25
    assert attempt.response_hash == _digest("response")
    assert attempt.request_digest == request.request_digest
    assert attempt.selection_digest == request.effective_selection_digest
    assert attempt.logical_call_id == "logical-call-live"
    assert attempt.parent_logical_call_id == "logical-call-live"
    assert attempt.lineage_reason == "optimizer_live"


@pytest.mark.asyncio
async def test_live_optimizer_fails_closed_for_unreviewed_worker_model() -> None:
    gateway = SimpleNamespace(
        policy=SimpleNamespace(network_enabled=True, worker=SimpleNamespace(model_id="unreviewed-model"))
    )
    with pytest.raises(ValueError, match="reviewed 5.4 ceiling"):
        await PromptOptimizer(gateway).optimize(_request())  # type: ignore[arg-type]
