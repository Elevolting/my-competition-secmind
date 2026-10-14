from __future__ import annotations

import hashlib
import json
import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Literal


class ComparativeEvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class ExperimentRun:
    experiment_id: str
    variant: Literal["v0.4", "v0.5", "control", "treatment"]
    case_id: str
    repetition: int
    success: bool
    precision: float | None
    recall: float | None
    latency_ms: int
    operator_actions: int
    provider_requests: int = 0
    cost_units: float = 0
    failures: tuple[str, ...] = ()
    artifact_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.experiment_id or not self.case_id or self.repetition < 1:
            raise ComparativeEvaluationError("experiment run identity is invalid")
        if self.latency_ms < 0 or self.operator_actions < 0 or self.provider_requests < 0 or self.cost_units < 0:
            raise ComparativeEvaluationError("experiment run counters cannot be negative")
        for metric in (self.precision, self.recall):
            if metric is not None and not 0 <= metric <= 1:
                raise ComparativeEvaluationError("precision and recall must be between zero and one")
        if any(not _valid_digest(item) for item in self.artifact_digests):
            raise ComparativeEvaluationError("experiment artifacts require non-zero SHA-256 digests")


@dataclass(frozen=True)
class ExperimentDefinition:
    experiment_id: str
    hypothesis: str
    dataset_digest: str
    label_version: str
    repetitions: int = 3
    minimum_cases: int = 1
    fixed_seed: int = 20260714
    controlled_variables: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    required_metrics: tuple[str, ...] = ("success_rate", "recall", "latency_ms")

    def __post_init__(self) -> None:
        if not self.experiment_id or not self.hypothesis or not self.label_version:
            raise ComparativeEvaluationError("experiment definition is incomplete")
        if not _valid_digest(self.dataset_digest):
            raise ComparativeEvaluationError("experiment dataset requires a non-zero SHA-256 digest")
        if self.repetitions < 3 or self.minimum_cases < 1:
            raise ComparativeEvaluationError("comparative experiments require at least three repetitions")


@dataclass(frozen=True)
class ExperimentReport:
    definition_digest: str
    complete: bool
    comparable: bool
    supported: bool
    metrics: dict[str, dict[str, Any]]
    deltas: dict[str, float | None]
    blockers: tuple[str, ...] = field(default_factory=tuple)
    failures: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def model_dump(self) -> dict[str, Any]:
        return {
            "report_format": "secmind-comparative-evaluation-v1",
            "definition_digest": self.definition_digest,
            "complete": self.complete,
            "comparable": self.comparable,
            "supported": self.supported,
            "metrics": self.metrics,
            "deltas": self.deltas,
            "blockers": list(self.blockers),
            "failures": list(self.failures),
        }


def evaluate_experiment(
    definition: ExperimentDefinition,
    runs: list[ExperimentRun],
    *,
    baseline: Literal["v0.4", "control"] = "v0.4",
    candidate: Literal["v0.5", "treatment"] = "v0.5",
    minimum_recall_gain: float = 0.0,
    maximum_latency_regression: float = 0.25,
    maximum_success_regression: float = 0.02,
) -> ExperimentReport:
    if minimum_recall_gain < -1 or maximum_latency_regression < 0 or not 0 <= maximum_success_regression <= 1:
        raise ComparativeEvaluationError("experiment thresholds are invalid")
    foreign = [run for run in runs if run.experiment_id != definition.experiment_id]
    if foreign:
        raise ComparativeEvaluationError("runs from another experiment cannot be mixed")
    by_variant = {name: [run for run in runs if run.variant == name] for name in (baseline, candidate)}
    case_ids = {name: {run.case_id for run in values} for name, values in by_variant.items()}
    expected_repetitions = set(range(1, definition.repetitions + 1))
    complete = all(
        len(case_ids[name]) >= definition.minimum_cases
        and all(
            {run.repetition for run in by_variant[name] if run.case_id == case_id} == expected_repetitions
            for case_id in case_ids[name]
        )
        for name in (baseline, candidate)
    )
    comparable = bool(case_ids[baseline] and case_ids[baseline] == case_ids[candidate])
    blockers: list[str] = []
    if not complete:
        blockers.append("case/repetition matrix is incomplete")
    if not comparable:
        blockers.append("baseline and candidate do not contain the same cases")
    if any(run.provider_requests or run.cost_units for run in runs):
        blockers.append("offline comparative experiment made a provider request or incurred model cost")
    metrics: dict[str, dict[str, Any]] = {name: _variant_metrics(values) for name, values in by_variant.items()}
    deltas = {
        "success_rate": _delta(metrics[candidate]["success_rate"]["mean"], metrics[baseline]["success_rate"]["mean"]),
        "precision": _delta(metrics[candidate]["precision"]["mean"], metrics[baseline]["precision"]["mean"]),
        "recall": _delta(metrics[candidate]["recall"]["mean"], metrics[baseline]["recall"]["mean"]),
        "latency_ratio": _ratio(metrics[candidate]["latency_ms"]["mean"], metrics[baseline]["latency_ms"]["mean"]),
        "operator_action_ratio": _ratio(
            metrics[candidate]["operator_actions"]["mean"], metrics[baseline]["operator_actions"]["mean"]
        ),
    }
    recall_delta = deltas["recall"]
    latency_ratio = deltas["latency_ratio"]
    if recall_delta is None or recall_delta < minimum_recall_gain:
        blockers.append("candidate recall did not meet the declared gain")
    if latency_ratio is None or latency_ratio > 1 + maximum_latency_regression:
        blockers.append("candidate latency exceeded the declared regression ceiling")
    success_delta = deltas["success_rate"]
    if success_delta is None or success_delta < -maximum_success_regression:
        blockers.append("candidate success rate exceeded the declared regression ceiling")
    failures = tuple(
        {
            "variant": run.variant,
            "case_id": run.case_id,
            "repetition": run.repetition,
            "reasons": list(run.failures) or ["unspecified failure"],
        }
        for run in runs
        if not run.success
    )
    return ExperimentReport(
        definition_digest=_definition_digest(definition),
        complete=complete,
        comparable=comparable,
        supported=not blockers,
        metrics=metrics,
        deltas=deltas,
        blockers=tuple(blockers),
        failures=failures,
    )


def _variant_metrics(runs: list[ExperimentRun]) -> dict[str, dict[str, float | int | None]]:
    return {
        "success_rate": _summary([1.0 if run.success else 0.0 for run in runs]),
        "precision": _summary([run.precision for run in runs if run.precision is not None]),
        "recall": _summary([run.recall for run in runs if run.recall is not None]),
        "latency_ms": _summary([float(run.latency_ms) for run in runs]),
        "operator_actions": _summary([float(run.operator_actions) for run in runs]),
    }


def _summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "mean": None, "median": None, "p95": None, "stdev": None}
    ordered = sorted(values)
    rank = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "count": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": ordered[rank],
        "stdev": statistics.pstdev(values),
    }


def _delta(candidate: Any, baseline: Any) -> float | None:
    if not isinstance(candidate, (int, float)) or not isinstance(baseline, (int, float)):
        return None
    return float(candidate) - float(baseline)


def _ratio(candidate: Any, baseline: Any) -> float | None:
    if not isinstance(candidate, (int, float)) or not isinstance(baseline, (int, float)) or baseline == 0:
        return None
    return float(candidate) / float(baseline)


def _definition_digest(definition: ExperimentDefinition) -> str:
    payload = {
        "experiment_id": definition.experiment_id,
        "hypothesis": definition.hypothesis,
        "dataset_digest": definition.dataset_digest,
        "label_version": definition.label_version,
        "repetitions": definition.repetitions,
        "minimum_cases": definition.minimum_cases,
        "fixed_seed": definition.fixed_seed,
        "controlled_variables": definition.controlled_variables,
        "exclusions": definition.exclusions,
        "required_metrics": definition.required_metrics,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _valid_digest(value: str) -> bool:
    normalized = value.removeprefix("sha256:")
    return len(normalized) == 64 and normalized != "0" * 64 and all(char in "0123456789abcdef" for char in normalized)
