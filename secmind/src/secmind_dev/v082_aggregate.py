"""Statistical aggregation for the v0.8.2 evaluation protocol.

The module keeps the 22-question security capability estimate separate from
the 60-question engineering-quality estimate.  It also makes the conditional
nature of paired semantics explicit: a semantic delta is calculated only for
tasks where both arms completed the primary path.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from statistics import mean, median
from typing import Any

from .v082_contracts import UNKNOWN_NOT_CONTROLLED, RunIdentity, canonical_digest, compare_identities

CAPABILITY_TASK_COUNT = 22
ENGINEERING_TASK_COUNT = 60
MIN_RANDOMIZED_BLOCKS = 5


class AggregationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TaskScore:
    task_id: str
    score: float
    outcome_score: float | None = None
    engineering_score: float | None = None
    outcome_correct: bool | None = None
    status: str = "SUCCESS"
    primary_status: str | None = None
    failure_type: str | None = None
    evidence_completeness: float | None = None
    precision: float | None = None
    recall: float | None = None
    finding_f1: float | None = None
    round_number: int = 1
    block: int | None = None
    arm: str = "unknown"
    scoring_mode: str = "security_finding"
    findings: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id:
            raise AggregationError("task_id is required")
        for name in (
            "score",
            "outcome_score",
            "engineering_score",
            "evidence_completeness",
            "precision",
            "recall",
            "finding_f1",
        ):
            value = getattr(self, name)
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                    raise AggregationError(f"{name} must be a finite number")
                if name not in {"score", "outcome_score", "engineering_score"} and not 0 <= float(value) <= 1:
                    raise AggregationError(f"{name} must be between 0 and 1")
                if name in {"score", "outcome_score", "engineering_score"} and not 0 <= float(value) <= 100:
                    raise AggregationError(f"{name} must be between 0 and 100")
        if isinstance(self.round_number, bool) or not isinstance(self.round_number, int) or self.round_number < 1:
            raise AggregationError("round_number must be positive")
        if self.block is not None and (
            isinstance(self.block, bool) or not isinstance(self.block, int) or self.block < 1
        ):
            raise AggregationError("block must be positive")
        object.__setattr__(self, "status", str(self.status).upper())
        object.__setattr__(
            self, "primary_status", None if self.primary_status is None else str(self.primary_status).upper()
        )
        object.__setattr__(self, "findings", tuple(item for item in self.findings if isinstance(item, Mapping)))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def capability_value(self) -> float:
        return float(self.outcome_score if self.outcome_score is not None else self.score)

    @property
    def engineering_value(self) -> float:
        if self.engineering_score is None:
            raise AggregationError("engineering_score is required for the engineering-quality view")
        return float(self.engineering_score)

    @property
    def primary_succeeded(self) -> bool:
        value = self.primary_status or self.status
        return value in {"SUCCESS", "COMPLETED"}

    @classmethod
    def from_mapping(
        cls, raw: Mapping[str, Any], *, arm: str = "unknown", round_number: int = 1, block: int | None = None
    ) -> TaskScore:
        if not isinstance(raw, Mapping):
            raise AggregationError("task score must be an object")
        score = _number(raw.get("score", raw.get("engineering_quality_score", raw.get("outcome_score", 0))), "score")
        findings = raw.get("findings", raw.get("finding_records", []))
        return cls(
            task_id=str(raw.get("task_id") or raw.get("id") or ""),
            score=score,
            outcome_score=_optional_number(raw.get("outcome_score", raw.get("capability_score"))),
            engineering_score=_optional_number(raw.get("engineering_score", raw.get("engineering_quality_score"))),
            outcome_correct=(raw.get("outcome_correct") if isinstance(raw.get("outcome_correct"), bool) else None),
            status=str(raw.get("status", raw.get("result_status", "SUCCESS"))),
            primary_status=(str(raw["primary_status"]) if raw.get("primary_status") is not None else None),
            failure_type=(str(raw["failure_type"]) if raw.get("failure_type") is not None else _failure_type(raw)),
            evidence_completeness=_optional_ratio(raw.get("evidence_completeness", raw.get("evidence_complete"))),
            precision=_optional_ratio(raw.get("precision")),
            recall=_optional_ratio(raw.get("recall")),
            finding_f1=_optional_ratio(raw.get("finding_f1", raw.get("f1"))),
            round_number=int(raw.get("round", raw.get("round_number", round_number))),
            block=(int(raw["block"]) if raw.get("block") is not None else block),
            arm=str(raw.get("arm", arm)),
            scoring_mode=str(raw.get("scoring_mode", "security_finding")),
            findings=tuple(findings) if isinstance(findings, list) else (),
            metadata=_mapping_or_empty(raw.get("metadata")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "score": self.score,
            "outcome_score": self.outcome_score,
            "engineering_score": self.engineering_score,
            "outcome_correct": self.outcome_correct,
            "status": self.status,
            "primary_status": self.primary_status,
            "failure_type": self.failure_type,
            "evidence_completeness": self.evidence_completeness,
            "precision": self.precision,
            "recall": self.recall,
            "finding_f1": self.finding_f1,
            "round": self.round_number,
            "block": self.block,
            "arm": self.arm,
            "scoring_mode": self.scoring_mode,
            "findings": [dict(item) for item in self.findings],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BlockPlan:
    block: int
    arm_order: tuple[str, ...]
    task_order: tuple[str, ...]
    seed: int
    scheme: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "block": self.block,
            "arm_order": list(self.arm_order),
            "task_order": list(self.task_order),
            "seed": self.seed,
            "scheme": self.scheme,
        }


def randomized_blocks(
    arms: Sequence[str],
    task_ids: Sequence[str],
    *,
    block_count: int = MIN_RANDOMIZED_BLOCKS,
    seed: int = 0,
    scheme: str = "latin-square",
) -> tuple[BlockPlan, ...]:
    """Create deterministic per-block arm/task randomization.

    ``latin-square`` rotates the arm order; ``abba`` alternates the order and
    is useful for a two-arm timeout/fallback experiment.  The task list is
    independently shuffled in every block so task and time-window effects do
    not remain perfectly collinear.
    """

    arm_values = tuple(dict.fromkeys(str(item) for item in arms if str(item)))
    task_values = tuple(dict.fromkeys(str(item) for item in task_ids if str(item)))
    if len(arm_values) < 2:
        raise AggregationError("at least two arms are required")
    if not task_values:
        raise AggregationError("at least one task is required")
    if block_count < MIN_RANDOMIZED_BLOCKS:
        raise AggregationError(f"at least {MIN_RANDOMIZED_BLOCKS} randomized blocks are required")
    if scheme not in {"latin-square", "abba"}:
        raise AggregationError("scheme must be latin-square or abba")
    plans: list[BlockPlan] = []
    for index in range(block_count):
        block_seed = _seed(seed, index, "block")
        if scheme == "abba" and len(arm_values) == 2:
            order = arm_values if index % 2 == 0 else tuple(reversed(arm_values))
        else:
            rotation = index % len(arm_values)
            order = arm_values[rotation:] + arm_values[:rotation]
            if index % 2 and len(arm_values) > 2:
                order = tuple(reversed(order))
        tasks = list(task_values)
        random.Random(block_seed).shuffle(tasks)  # noqa: S311  # nosec B311
        plans.append(BlockPlan(index + 1, tuple(order), tuple(tasks), block_seed, scheme))
    return tuple(plans)


def validate_randomized_blocks(plans: Sequence[BlockPlan], *, minimum: int = MIN_RANDOMIZED_BLOCKS) -> dict[str, Any]:
    if len(plans) < minimum:
        return {"valid": False, "reason": f"requires at least {minimum} blocks", "block_count": len(plans)}
    orders = [plan.arm_order for plan in plans]
    distinct_orders = len(set(orders))
    return {
        "valid": distinct_orders > 1 and all(plan.task_order for plan in plans),
        "block_count": len(plans),
        "distinct_arm_orders": distinct_orders,
        "task_orders_distinct": len({plan.task_order for plan in plans}),
    }


def aggregate_scores(
    rows: Sequence[TaskScore],
    *,
    capability_task_ids: Sequence[str] | None = None,
    engineering_task_ids: Sequence[str] | None = None,
    capability_limit: int = CAPABILITY_TASK_COUNT,
    engineering_limit: int = ENGINEERING_TASK_COUNT,
    randomized_block_count: int | None = None,
    findings: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Aggregate all rounds by mean/median, never by last-round overwrite."""

    values = tuple(rows)
    if not values:
        raise AggregationError("cannot aggregate an empty score set")
    capability_ids = set(capability_task_ids or ())
    engineering_ids = set(engineering_task_ids or ())
    if capability_ids:
        capability_rows = [item for item in values if item.task_id in capability_ids]
        missing_capability = sorted(capability_ids - {item.task_id for item in capability_rows})
    else:
        capability_rows = [item for item in values if _capability_eligible(item)]
        missing_capability = []
        if len({item.task_id for item in capability_rows}) > capability_limit:
            raise AggregationError("capability aggregation requires an explicit 22-task roster")
    if engineering_ids:
        engineering_rows = [item for item in values if item.task_id in engineering_ids]
        missing_engineering = sorted(engineering_ids - {item.task_id for item in engineering_rows})
    else:
        engineering_rows = list(values)
        missing_engineering = []
    if len({item.task_id for item in capability_rows}) > capability_limit:
        raise AggregationError(f"capability denominator exceeds {capability_limit} tasks")
    if len({item.task_id for item in engineering_rows}) > engineering_limit:
        raise AggregationError(f"engineering denominator exceeds {engineering_limit} tasks")

    rounds = _round_summary(values)
    block_summary = _block_summary(values)
    reliability = _reliability(values)
    finding_values = tuple(findings) or tuple(item for row in values for item in row.findings)
    finding_stats = finding_metrics(finding_values)
    capability_scores = [item.capability_value for item in capability_rows]
    engineering_scores = [
        float(item.engineering_score) for item in engineering_rows if item.engineering_score is not None
    ]
    evidence_values = [item.evidence_completeness for item in values if item.evidence_completeness is not None]
    return {
        "schema_version": "secmind-aggregate-v0.8.2",
        "task_count": len(values),
        "capability": {
            "profile": "security_finding_22",
            "task_roster_size": len(capability_ids)
            if capability_ids
            else len({item.task_id for item in capability_rows}),
            "observed_tasks": len({item.task_id for item in capability_rows}),
            "missing_tasks": missing_capability,
            "score_field": "outcome_score",
            "mean": _round(mean(capability_scores)) if capability_scores else None,
            "median": _round(median(capability_scores)) if capability_scores else None,
            "score": _round(mean(capability_scores)) if capability_scores else None,
        },
        "engineering": {
            "profile": "engineering_quality_60",
            "task_roster_size": len(engineering_ids)
            if engineering_ids
            else len({item.task_id for item in engineering_rows}),
            "observed_tasks": len({item.task_id for item in engineering_rows}),
            "missing_tasks": missing_engineering,
            "score_field": "engineering_score",
            "mean": _round(mean(engineering_scores)) if engineering_scores else None,
            "median": _round(median(engineering_scores)) if engineering_scores else None,
            "score": _round(mean(engineering_scores)) if engineering_scores else None,
        },
        # Compatibility aliases make it hard for a dashboard to accidentally
        # use engineering score as the 22-question capability score.
        "capability_score": _round(mean(capability_scores)) if capability_scores else None,
        "engineering_quality_score": _round(mean(engineering_scores)) if engineering_scores else None,
        "rounds": rounds,
        "blocks": block_summary,
        "reliability": reliability,
        "metrics": {
            "finding_precision": finding_stats["precision"],
            "finding_recall": finding_stats["recall"],
            "finding_f1": finding_stats["f1"],
            "verified_precision": finding_stats["verified_precision"],
            "evidence_grounded_f1": finding_stats["evidence_grounded_f1"],
            "evidence_completeness": _ratio(sum(evidence_values), len(evidence_values))
            if evidence_values
            else finding_stats["evidence_completeness"],
            "end_to_end_reliability": reliability["end_to_end_success_rate"],
        },
        "finding_metrics": finding_stats,
        "randomization": {
            "required_blocks": MIN_RANDOMIZED_BLOCKS,
            "observed_blocks": len({item.block for item in values if item.block is not None}),
            "valid": randomized_block_count is None or randomized_block_count >= MIN_RANDOMIZED_BLOCKS,
        },
    }


def compare_arms(
    rows_by_arm: Mapping[str, Sequence[TaskScore]],
    *,
    anchor: str,
    enhanced: str,
    identities: Mapping[str, RunIdentity] | None = None,
    bootstrap_iterations: int = 2_000,
    seed: int = 0,
) -> dict[str, Any]:
    if anchor not in rows_by_arm or enhanced not in rows_by_arm:
        raise AggregationError("anchor and enhanced arms must be present")
    control = {"status": UNKNOWN_NOT_CONTROLLED, "controlled": False, "fields": []}
    if identities is not None and anchor in identities and enhanced in identities:
        control = compare_identities(identities[anchor], identities[enhanced])
    left = _index_rows(rows_by_arm[anchor])
    right = _index_rows(rows_by_arm[enhanced])
    keys = sorted(set(left) & set(right))
    end_to_end_left = [row.capability_value for row in rows_by_arm[anchor]]
    end_to_end_right = [row.capability_value for row in rows_by_arm[enhanced]]
    paired_all = [(_value(right[key]), _value(left[key])) for key in keys]
    conditional = [
        (right_value, left_value)
        for key, (right_value, left_value) in zip(keys, paired_all, strict=True)
        if right[key].primary_succeeded and left[key].primary_succeeded
    ]
    deltas = [right_value - left_value for right_value, left_value in conditional]
    task_cluster = _cluster_deltas(keys, left, right)
    block_count = len(
        {left[key].block for key in keys if left[key].block is not None}
        & {right[key].block for key in keys if right[key].block is not None}
    )
    ci = bootstrap_ci(task_cluster, iterations=bootstrap_iterations, seed=seed)
    sign = paired_sign_test(deltas)
    permutation = paired_permutation_test(deltas, iterations=bootstrap_iterations, seed=seed)
    return {
        "schema_version": "secmind-arm-compare-v0.8.2",
        "anchor_arm": anchor,
        "enhanced_arm": enhanced,
        "control": control,
        "controlled_comparison": control["controlled"] and block_count >= MIN_RANDOMIZED_BLOCKS,
        "status": (
            "CONTROLLED"
            if control["controlled"] and block_count >= MIN_RANDOMIZED_BLOCKS
            else UNKNOWN_NOT_CONTROLLED
            if control["status"] == UNKNOWN_NOT_CONTROLLED or block_count < MIN_RANDOMIZED_BLOCKS
            else "MISMATCH"
        ),
        "paired_tasks": len(keys),
        "success_conditional_paired_tasks": len(conditional),
        "success_conditional_semantics": {
            "definition": "both anchor and enhanced primary paths succeeded",
            "anchor_mean": _round(
                mean([left[key].capability_value for key in keys if key in left and left[key].primary_succeeded])
            )
            if keys
            else None,
            "enhanced_mean": _round(
                mean([right[key].capability_value for key in keys if key in right and right[key].primary_succeeded])
            )
            if keys
            else None,
            "delta_mean": _round(mean(deltas)) if deltas else None,
            "cluster_bootstrap_95_ci": ci,
            "paired_sign_test": sign,
            "paired_permutation_test": permutation,
            "undefined_when_no_joint_success": not bool(deltas),
        },
        "end_to_end": {
            "anchor_mean": _round(mean(end_to_end_left)) if end_to_end_left else None,
            "enhanced_mean": _round(mean(end_to_end_right)) if end_to_end_right else None,
            "delta_mean": _round(mean(end_to_end_right) - mean(end_to_end_left))
            if end_to_end_left and end_to_end_right
            else None,
            "anchor_task_count": len(end_to_end_left),
            "enhanced_task_count": len(end_to_end_right),
        },
        "blocks": block_count,
        "views": {
            "anchor": _arm_view(rows_by_arm[anchor], "anchor"),
            "delta_proposal": _arm_view(rows_by_arm[enhanced], "delta_proposal"),
            "accepted_delta": _arm_view(rows_by_arm[enhanced], "accepted_delta"),
            "enhanced": _arm_view(rows_by_arm[enhanced], "enhanced"),
        },
    }


def bootstrap_ci(
    values: Sequence[float], *, iterations: int = 2_000, seed: int = 0, confidence: float = 0.95
) -> dict[str, Any] | None:
    items = [float(value) for value in values]
    if not items:
        return None
    if len(items) == 1:
        return {"lower": _round(items[0]), "upper": _round(items[0]), "confidence": confidence, "unit": "task_cluster"}
    if iterations < 100:
        raise AggregationError("bootstrap_iterations must be at least 100")
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    samples = [mean(rng.choice(items) for _ in items) for _ in range(iterations)]
    alpha = (1 - confidence) / 2
    return {
        "lower": _round(_quantile(samples, alpha)),
        "upper": _round(_quantile(samples, 1 - alpha)),
        "confidence": confidence,
        "unit": "task_cluster",
        "iterations": iterations,
    }


def paired_sign_test(deltas: Sequence[float]) -> dict[str, Any]:
    nonzero = [float(value) for value in deltas if value != 0]
    if not nonzero:
        return {"n": 0, "positive": 0, "negative": 0, "p_two_sided": None}
    positive = sum(value > 0 for value in nonzero)
    negative = len(nonzero) - positive
    tail = sum(math.comb(len(nonzero), index) for index in range(min(positive, negative) + 1)) / (2 ** len(nonzero))
    return {
        "n": len(nonzero),
        "positive": positive,
        "negative": negative,
        "p_two_sided": _round(min(1.0, 2 * tail)),
    }


def paired_permutation_test(deltas: Sequence[float], *, iterations: int = 2_000, seed: int = 0) -> dict[str, Any]:
    items = [float(value) for value in deltas if value != 0]
    if not items:
        return {"n": 0, "p_two_sided": None, "iterations": iterations}
    if iterations < 100:
        raise AggregationError("permutation iterations must be at least 100")
    observed = abs(mean(items))
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    exceed = 0
    for _ in range(iterations):
        simulated = mean(value if rng.getrandbits(1) else -value for value in items)
        if abs(simulated) >= observed:
            exceed += 1
    return {"n": len(items), "p_two_sided": _round((exceed + 1) / (iterations + 1)), "iterations": iterations}


def finding_metrics(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Deduplicate semantic fingerprints before precision accounting."""

    groups: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(findings):
        if not isinstance(raw, Mapping):
            continue
        fingerprint = str(raw.get("fingerprint") or _finding_fingerprint(raw, index))
        current = groups.setdefault(
            fingerprint,
            {"expected": False, "predicted": False, "verified": False, "evidence": False},
        )
        current["predicted"] = True
        current["expected"] = bool(current["expected"] or raw.get("expected") or raw.get("true_positive"))
        current["verified"] = bool(current["verified"] or raw.get("verified"))
        current["evidence"] = bool(current["evidence"] or raw.get("evidence_valid") or raw.get("evidence_complete"))
    predicted = sum(item["predicted"] for item in groups.values())
    true_positive = sum(item["predicted"] and item["expected"] for item in groups.values())
    false_positive = sum(item["predicted"] and not item["expected"] for item in groups.values())
    expected = sum(item["expected"] for item in groups.values())
    verified_predicted = sum(item["predicted"] and item["verified"] for item in groups.values())
    verified_tp = sum(item["predicted"] and item["verified"] and item["expected"] for item in groups.values())
    grounded_tp = sum(item["predicted"] and item["expected"] and item["evidence"] for item in groups.values())
    grounded_fp = sum(item["predicted"] and not item["expected"] and item["evidence"] for item in groups.values())
    evidence_total = sum(item["predicted"] for item in groups.values())
    evidence_complete = sum(item["predicted"] and item["evidence"] for item in groups.values())
    return {
        "unique_fingerprints": len(groups),
        "predicted": predicted,
        "expected": expected,
        "tp": true_positive,
        "fp": false_positive,
        "fn": max(0, expected - true_positive),
        "precision": _ratio(true_positive, predicted),
        "recall": _ratio(true_positive, expected),
        "f1": _f1(true_positive, false_positive, max(0, expected - true_positive)),
        "verified_predicted": verified_predicted,
        "verified_precision": _ratio(verified_tp, verified_predicted),
        "evidence_complete": evidence_complete,
        "evidence_total": evidence_total,
        "evidence_completeness": _ratio(evidence_complete, evidence_total),
        "evidence_grounded_tp": grounded_tp,
        "evidence_grounded_fp": grounded_fp,
        "evidence_grounded_f1": _f1(grounded_tp, grounded_fp, max(0, expected - grounded_tp)),
    }


def _index_rows(rows: Sequence[TaskScore]) -> dict[tuple[int | None, str, int], TaskScore]:
    result: dict[tuple[int | None, str, int], TaskScore] = {}
    for row in rows:
        key = (row.block, row.task_id, row.round_number)
        if key in result:
            raise AggregationError(f"duplicate arm/task/block/round score: {key}")
        result[key] = row
    return result


def _cluster_deltas(
    keys: Sequence[tuple[int | None, str, int]], left: Mapping[Any, TaskScore], right: Mapping[Any, TaskScore]
) -> list[float]:
    by_task: dict[str, list[float]] = defaultdict(list)
    for key in keys:
        if left[key].primary_succeeded and right[key].primary_succeeded:
            by_task[key[1]].append(right[key].capability_value - left[key].capability_value)
    return [mean(values) for values in by_task.values()]


def _round(value: float) -> float:
    return round(float(value), 6)


def _ratio(numerator: float, denominator: float) -> float | None:
    return _round(numerator / denominator) if denominator else None


def _f1(tp: int, fp: int, fn: int) -> float | None:
    return _ratio(2 * tp, 2 * tp + fp + fn)


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise AggregationError(f"{field_name} must be a finite number")
    return float(value)


def _optional_number(value: Any) -> float | None:
    return None if value is None else _number(value, "score")


def _optional_ratio(value: Any) -> float | None:
    result = _optional_number(value)
    if result is None:
        return None
    if result > 1 and result <= 100:
        result /= 100
    if not 0 <= result <= 1:
        raise AggregationError("ratio must be between 0 and 1 or 0 and 100")
    return result


def _failure_type(raw: Mapping[str, Any]) -> str | None:
    attempts = raw.get("attempts", raw.get("provider_attempts"))
    if isinstance(attempts, list):
        for attempt in reversed(attempts):
            if isinstance(attempt, Mapping) and attempt.get("error_type"):
                return str(attempt["error_type"])
    return None


def _capability_eligible(row: TaskScore) -> bool:
    return bool(row.metadata.get("capability_eligible", row.scoring_mode == "security_finding"))


def _round_summary(rows: Sequence[TaskScore]) -> list[dict[str, Any]]:
    grouped: dict[int, list[TaskScore]] = defaultdict(list)
    for row in rows:
        grouped[row.round_number].append(row)
    result = []
    for number, items in sorted(grouped.items()):
        capability = [item.capability_value for item in items if _capability_eligible(item)]
        engineering = [float(item.engineering_score) for item in items if item.engineering_score is not None]
        result.append(
            {
                "round": number,
                "task_count": len(items),
                "capability_mean": _round(mean(capability)) if capability else None,
                "engineering_mean": _round(mean(engineering)) if engineering else None,
                "primary_success_rate": _ratio(sum(item.primary_succeeded for item in items), len(items)),
            }
        )
    return result


def _block_summary(rows: Sequence[TaskScore]) -> list[dict[str, Any]]:
    grouped: dict[int, list[TaskScore]] = defaultdict(list)
    for row in rows:
        if row.block is not None:
            grouped[row.block].append(row)
    return [
        {
            "block": number,
            "task_count": len(items),
            "capability_mean": _round(mean(item.capability_value for item in items)) if items else None,
            "engineering_mean": (
                _round(mean(float(item.engineering_score) for item in items if item.engineering_score is not None))
                if any(item.engineering_score is not None for item in items)
                else None
            ),
        }
        for number, items in sorted(grouped.items())
    ]


def _reliability(rows: Sequence[TaskScore]) -> dict[str, Any]:
    failure_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        if not row.primary_succeeded:
            failure_counts[row.failure_type or row.primary_status or row.status or "unknown"] += 1
    return {
        "primary_success_rate": _ratio(sum(item.primary_succeeded for item in rows), len(rows)),
        "end_to_end_success_rate": _ratio(sum(item.status in {"SUCCESS", "COMPLETED"} for item in rows), len(rows)),
        "failure_counts": dict(sorted(failure_counts.items())),
        "failure_rates": {key: _ratio(value, len(rows)) for key, value in sorted(failure_counts.items())},
        "observations": len(rows),
    }


def _finding_fingerprint(raw: Mapping[str, Any], index: int) -> str:
    return canonical_digest(
        {
            "path": str(raw.get("path") or raw.get("file") or "").casefold(),
            "line": raw.get("line"),
            "cwe": str(raw.get("cwe") or raw.get("rule_id") or raw.get("classification") or "").casefold(),
            "root_cause": raw.get("root_cause") or raw.get("description") or index,
        }
    )


def _seed(seed: int, block: int, label: str) -> int:
    material = f"{seed}:{block}:{label}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _value(row: TaskScore) -> float:
    return row.capability_value


def _mapping_or_empty(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _arm_view(rows: Sequence[TaskScore], label: str) -> dict[str, Any]:
    return {
        "label": label,
        "task_count": len(rows),
        "capability_mean": _round(mean(item.capability_value for item in rows)) if rows else None,
        "engineering_mean": (
            _round(mean(float(item.engineering_score) for item in rows if item.engineering_score is not None))
            if any(item.engineering_score is not None for item in rows)
            else None
        ),
    }


__all__ = [
    "AggregationError",
    "BlockPlan",
    "CAPABILITY_TASK_COUNT",
    "ENGINEERING_TASK_COUNT",
    "MIN_RANDOMIZED_BLOCKS",
    "TaskScore",
    "aggregate_scores",
    "bootstrap_ci",
    "compare_arms",
    "finding_metrics",
    "paired_permutation_test",
    "paired_sign_test",
    "randomized_blocks",
    "validate_randomized_blocks",
]
