from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from secmind.agents import DeltaCriticAgent, DeltaCriticDecision
from secmind.direct_anchor_pipeline import DeltaAction, DeltaDisposition, TypedDelta
from secmind.model_router import ModelTaskKind
from secmind.schemas import AgentState, Finding, ModelUsage, RunStatus, Scenario, TaskRequest
from secmind.task_contract import seal_independence_proof, validate_independence_proof


def _proof(**overrides: object):
    values: dict[str, object] = {
        "provider": "deepseek",
        "model_family": "deepseek",
        "model_id": "deepseek-v4-flash",
        "method_family": "canonical-primary-vs-delta-critic",
        "primary_provider": "dashscope",
        "critic_provider": "deepseek",
        "primary_model_family": "qwen",
        "critic_model_family": "deepseek",
        "primary_model_id": "qwen-plus",
        "critic_model_id": "deepseek-v4-flash",
        "primary_request_lineage": "p" * 64,
        "critic_request_lineage": "c" * 64,
        "primary_method_lineage": "primary-method-lineage",
        "critic_method_lineage": "critic-method-lineage",
        "primary_input_slice_digest": "1" * 64,
        "critic_input_slice_digest": "2" * 64,
        "primary_context_digest": "3" * 64,
        "critic_context_digest": "4" * 64,
        "compared_lineage_ids": ["primary:p", "critic:c"],
        "independent": True,
    }
    values.update(overrides)
    return seal_independence_proof(**values)


def test_same_model_different_labels_is_not_independent() -> None:
    proof = _proof(
        provider="dashscope",
        model_family="qwen",
        model_id="qwen-plus",
        critic_provider="dashscope",
        critic_model_family="qwen",
        critic_model_id="qwen-plus",
    )

    independent, reasons = validate_independence_proof(proof)

    assert not independent
    assert "same_provider_model_lineage" in reasons


def test_different_models_with_the_same_context_are_not_independent() -> None:
    proof = _proof(critic_model_id="qwen-turbo", critic_model_family="qwen", critic_context_digest="3" * 64)

    independent, reasons = validate_independence_proof(proof)

    assert not independent
    assert "same_context_digest" in reasons


def test_isolated_provider_method_request_and_context_are_independent() -> None:
    proof = _proof()

    independent, reasons = validate_independence_proof(proof)

    assert independent
    assert reasons == ()


def test_route_label_or_tampered_proof_cannot_authorize_independence() -> None:
    independent, reasons = validate_independence_proof({"route_is_independent": True})
    assert not independent
    assert reasons == ("proof_invalid_or_unsealed",)

    payload = _proof().model_dump(mode="json")
    payload["critic_model_id"] = "qwen-turbo"
    independent, reasons = validate_independence_proof(payload)
    assert not independent
    assert reasons == ("proof_invalid_or_unsealed",)


def _critic_state(*, primary_model_id: str = "qwen-plus") -> AgentState:
    primary = Finding(
        finding_id="primary",
        rule_id="CWE-89",
        severity="HIGH",
        confidence="HIGH",
        path="app.py",
        line=7,
        title="primary finding",
        description="source reaches a query sink",
        evidence_ids=["evidence-primary"],
    )
    candidate = primary.model_copy(update={"finding_id": "candidate"})
    delta = TypedDelta(
        delta_id="delta-1",
        run_id="critic-run",
        cluster_id="cluster-1",
        candidate_ids=("candidate-1",),
        action=DeltaAction.CORRECT,
        disposition=DeltaDisposition.QUARANTINED,
        target_finding_id=primary.finding_id,
        finding=candidate,
        evidence_ids=tuple(candidate.evidence_ids),
        producer_ids=("independent-scout",),
        reason_code="typed-test",
        evidence_complete=True,
        semantic_checks={"source": True},
        admission_ready=False,
        anchor_semantic_digest="a" * 64,
        gate_digest="b" * 64,
    )
    return AgentState(
        run_id="critic-run",
        task=TaskRequest(objective="audit source", autonomy_policy="automatic"),
        scenario=Scenario.CODE_AUDIT,
        status=RunStatus.RUNNING,
        findings=[primary],
        audit_coverage={
            "direct_anchor_pipeline": True,
            "primary_finding_ids": [primary.finding_id],
            "primary_route": {
                "task_kind": "primary_review",
                "profile": "primary-strong",
                "model_id": primary_model_id,
                "provider": "dashscope",
                "request_sha256": "1" * 64,
                "context_sha256": "2" * 64,
                "input_slice_digest": "3" * 64,
                "lineage_id": "primary-call-lineage",
                "prompt_version": "primary-v1",
            },
            "typed_deltas": [delta.model_dump(mode="json")],
        },
    )


class _CriticGateway:
    def __init__(self, *, model_id: str, provider: str, context_digest: str) -> None:
        self.meta = SimpleNamespace(
            usage=ModelUsage(provider_requests=1),
            model_id=model_id,
            provider=provider,
            prompt_version="direct-delta-critic-v2",
            request_sha256="4" * 64,
            logical_call_id="critic-call-lineage",
            context_digest=context_digest,
            route_profile="critic-bounded",
            route_lane="lightweight",
            route_task_kind=ModelTaskKind.CRITIC_REVIEW.value,
        )

    async def structured(self, **kwargs: Any) -> tuple[DeltaCriticDecision, Any]:
        return (
            DeltaCriticDecision(status="accepted", rationale="bounded", conflict_delta_ids=["delta-1"]),
            self.meta,
        )


@pytest.mark.asyncio
async def test_critic_same_model_different_route_labels_stays_shadow() -> None:
    state = _critic_state()

    await DeltaCriticAgent(
        _CriticGateway(model_id="qwen-plus", provider="dashscope", context_digest="5" * 64)  # type: ignore[arg-type]
    ).run(state)

    coverage = state.audit_coverage["delta_critic"]
    assert coverage["status"] == "shadow"
    assert coverage["route_is_independent"] is False
    assert coverage["authorized_delta_ids"] == []
    assert "same_provider_model_lineage" in coverage["independence_reason"]


@pytest.mark.asyncio
async def test_critic_isolated_model_method_and_context_can_be_independent() -> None:
    state = _critic_state()

    await DeltaCriticAgent(
        _CriticGateway(
            model_id="deepseek-v4-flash",
            provider="deepseek",
            context_digest="5" * 64,
        )  # type: ignore[arg-type]
    ).run(state)

    coverage = state.audit_coverage["delta_critic"]
    assert coverage["status"] == "completed"
    assert coverage["route_is_independent"] is True
    assert coverage["authorized_delta_ids"] == ["delta-1"]
    assert coverage["independence_proof"]["primary_request_lineage"] == "1" * 64
    assert coverage["independence_proof"]["critic_request_lineage"] == "4" * 64
