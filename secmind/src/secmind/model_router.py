from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from secmind.model_policy import ModelCatalogEntry, ModelPolicy

MODEL_ROUTER_VERSION = "secmind-model-router-1.1"
PRIMARY_ROUTE_PROFILE = "primary-strong"
CRITIC_ROUTE_PROFILE = "critic-bounded"
FALLBACK_ROUTE_PROFILE = "fallback-bounded"


class ModelTaskKind(StrEnum):
    """Stable, auditable labels applied before a provider request is built."""

    PLANNING = "planning"
    PRIMARY_REVIEW = "primary_review"
    REASONING = "reasoning"
    VERIFICATION = "verification"
    CRITIC_REVIEW = "critic_review"
    PROMPT_OPTIMIZATION = "prompt_optimization"
    CLASSIFICATION = "classification"
    SUMMARIZATION = "summarization"
    EXTRACTION = "extraction"
    GENERAL = "general"


class ModelLane(StrEnum):
    REASONING = "reasoning"
    LIGHTWEIGHT = "lightweight"


@dataclass(frozen=True, slots=True)
class ModelRouteDecision:
    task_kind: ModelTaskKind
    lane: ModelLane
    primary: ModelCatalogEntry
    fallback: ModelCatalogEntry
    router_version: str
    rationale: str
    primary_profile: str = PRIMARY_ROUTE_PROFILE
    fallback_profile: str = FALLBACK_ROUTE_PROFILE

    @property
    def route(self) -> str:
        return f"{self.task_kind.value}:{self.lane.value}"


class ModelRouter:
    """Deterministically route bounded tasks without inspecting untrusted content."""

    _REASONING_TASKS = frozenset(
        {
            ModelTaskKind.PLANNING,
            ModelTaskKind.PRIMARY_REVIEW,
            ModelTaskKind.REASONING,
            ModelTaskKind.VERIFICATION,
        }
    )
    _LIGHTWEIGHT_TASKS = frozenset(
        {
            ModelTaskKind.CRITIC_REVIEW,
            ModelTaskKind.PROMPT_OPTIMIZATION,
            ModelTaskKind.CLASSIFICATION,
            ModelTaskKind.SUMMARIZATION,
            ModelTaskKind.EXTRACTION,
        }
    )

    def __init__(self, policy: ModelPolicy) -> None:
        self._policy = policy

    def route(self, task_kind: ModelTaskKind | str | None, *, role: str) -> ModelRouteDecision:
        kind = ModelTaskKind(task_kind or ModelTaskKind.GENERAL)
        if kind in self._REASONING_TASKS:
            lane = ModelLane.REASONING
            primary = self._policy.planner
            rationale = "Bounded planning, primary review, reasoning, and verification use the reasoning model."
        elif kind in self._LIGHTWEIGHT_TASKS:
            lane = ModelLane.LIGHTWEIGHT
            primary = self._policy.worker
            rationale = "Critique, optimization, classification, summarization, and extraction use the worker model."
        elif role == "planner":
            # Backward compatibility for call sites that have not supplied a
            # task label yet. The legacy role remains part of the request hash.
            lane = ModelLane.REASONING
            primary = self._policy.planner
            rationale = "Legacy planner role defaults to the reasoning model."
        else:
            lane = ModelLane.LIGHTWEIGHT
            primary = self._policy.worker
            rationale = "Legacy worker role defaults to the worker model."
        return ModelRouteDecision(
            task_kind=kind,
            lane=lane,
            primary=primary,
            fallback=self._policy.fallback,
            router_version=MODEL_ROUTER_VERSION,
            rationale=rationale,
            primary_profile=(CRITIC_ROUTE_PROFILE if kind is ModelTaskKind.CRITIC_REVIEW else PRIMARY_ROUTE_PROFILE),
        )


__all__ = [
    "FALLBACK_ROUTE_PROFILE",
    "CRITIC_ROUTE_PROFILE",
    "MODEL_ROUTER_VERSION",
    "ModelLane",
    "ModelRouteDecision",
    "ModelRouter",
    "ModelTaskKind",
    "PRIMARY_ROUTE_PROFILE",
]
