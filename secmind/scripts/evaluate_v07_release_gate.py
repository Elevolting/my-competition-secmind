from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secmind_dev.v07_evaluation import main as abcd_protocol_main

FOUR_CWE_SCOPE = frozenset({22, 78, 79, 89})
PASSING_STATUSES = frozenset({"complete", "completed", "success", "succeeded"})
RECOVERY_STATUS = "recovery_required"


@dataclass(frozen=True)
class GoldCase:
    case_id: str
    vulnerable: bool
    cwe: int
    category: str | None = None


@dataclass(frozen=True)
class Prediction:
    vulnerable: bool | None
    cwe: int | None


@dataclass(frozen=True)
class Run:
    repetition: int | str
    predictions: Mapping[str, Prediction]
    status: str
    synthetic: bool = False


@dataclass(frozen=True)
class Arm:
    name: str
    runs: tuple[Run, ...]
    expected_runs: int
    recovery_required: int


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_gold(path: Path) -> dict[str, GoldCase]:
    raw = _load_json(path)
    cases = raw.get("cases", raw) if isinstance(raw, dict) else raw
    if isinstance(cases, dict):
        entries: Iterable[tuple[str | None, Any]] = cases.items()
    elif isinstance(cases, list):
        entries = ((None, item) for item in cases)
    else:
        raise ValueError("gold must contain a cases mapping or list")

    result: dict[str, GoldCase] = {}
    for fallback_id, value in entries:
        if not isinstance(value, dict):
            raise ValueError("each gold case must be an object")
        case_id = str(value.get("case_id") or fallback_id or "")
        if not case_id:
            raise ValueError("gold case is missing case_id")
        vulnerable = value.get("gold_vulnerable", value.get("vulnerable"))
        cwe = _safe_int(value.get("gold_cwe", value.get("cwe")))
        if not isinstance(vulnerable, bool) or cwe is None:
            raise ValueError(f"gold case {case_id!r} needs boolean vulnerability and integer CWE")
        if case_id in result:
            raise ValueError(f"duplicate gold case: {case_id}")
        result[case_id] = GoldCase(
            case_id=case_id,
            vulnerable=vulnerable,
            cwe=cwe,
            category=value.get("category"),
        )
    if not result:
        raise ValueError("gold is empty")
    return result


def _prediction(value: Mapping[str, Any]) -> Prediction:
    vulnerable = value.get("predicted_vulnerable", value.get("vulnerable"))
    if vulnerable not in (True, False, None):
        raise ValueError("predicted vulnerability must be true, false, or null")
    return Prediction(
        vulnerable=vulnerable,
        cwe=_safe_int(value.get("predicted_cwe", value.get("cwe"))),
    )


def _prediction_map(values: Sequence[Any], gold_ids: set[str]) -> dict[str, Prediction]:
    result: dict[str, Prediction] = {}
    for value in values:
        if not isinstance(value, dict) or not value.get("case_id"):
            raise ValueError("every prediction needs case_id")
        case_id = str(value["case_id"])
        if case_id not in gold_ids:
            raise ValueError(f"prediction references unknown case: {case_id}")
        if case_id in result:
            raise ValueError(f"duplicate prediction for case: {case_id}")
        result[case_id] = _prediction(value)
    return result


def load_arm(raw: Mapping[str, Any], gold_ids: set[str], *, fallback_name: str) -> Arm:
    raw_runs = raw.get("runs")
    if not isinstance(raw_runs, list):
        raw_predictions = raw.get("predictions", raw.get("case_results"))
        if not isinstance(raw_predictions, list):
            raise ValueError("arm must contain runs or predictions")
        raw_runs = [
            {
                "repetition": 1,
                "predictions": raw_predictions,
                "status": raw.get("status"),
            }
        ]

    runs: list[Run] = []
    grouped: dict[int | str, list[Mapping[str, Any]]] = {}
    for index, value in enumerate(raw_runs, 1):
        if not isinstance(value, dict) or not isinstance(value.get("predictions"), list):
            raise ValueError("each run must contain a predictions list")
        repetition = value.get("repetition", index)
        grouped.setdefault(repetition, []).append(value)

    seen_repetitions: set[int | str] = set(grouped)
    for repetition, parts in grouped.items():
        predictions: dict[str, Prediction] = {}
        explicit_statuses = [str(part["status"]).lower() for part in parts if part.get("status")]
        for part in parts:
            part_predictions = _prediction_map(part["predictions"], gold_ids)
            overlap = set(predictions) & set(part_predictions)
            if overlap:
                raise ValueError(
                    f"repetition {repetition!r} contains duplicate cases across batches: {sorted(overlap)[:3]}"
                )
            predictions.update(part_predictions)
        inferred = (
            "completed"
            if len(predictions) == len(gold_ids) and all(item.vulnerable is not None for item in predictions.values())
            else "partial"
        )
        status = (
            RECOVERY_STATUS
            if RECOVERY_STATUS in explicit_statuses
            else (
                "failed"
                if any(item in {"failed", "error"} for item in explicit_statuses)
                else (
                    next(
                        (item for item in explicit_statuses if item not in PASSING_STATUSES),
                        "completed",
                    )
                    if explicit_statuses
                    else inferred
                )
            )
        )
        runs.append(
            Run(
                repetition=repetition,
                predictions=predictions,
                status=status,
            )
        )

    numeric_candidates = [len(runs)]
    for key in ("configured_repetitions", "operational_runs_total", "repetitions"):
        value = raw.get(key)
        if isinstance(value, int):
            numeric_candidates.append(value)
    failed_repetitions = raw.get("failed_logical_repetitions", [])
    if isinstance(failed_repetitions, list):
        numeric_candidates.append(len(runs) + sum(item not in seen_repetitions for item in failed_repetitions))
    expected_runs = max(numeric_candidates)

    recovery = sum(run.status == RECOVERY_STATUS for run in runs)
    if str(raw.get("failed_run_status", "")).lower() == RECOVERY_STATUS:
        recovery = max(recovery, len(failed_repetitions) or 1)

    for failed in failed_repetitions if isinstance(failed_repetitions, list) else []:
        if failed not in seen_repetitions:
            runs.append(
                Run(
                    failed,
                    {},
                    str(raw.get("failed_run_status") or "failed").lower(),
                    True,
                )
            )
            seen_repetitions.add(failed)
    while len(runs) < expected_runs:
        ordinal = len(runs) + 1
        runs.append(Run(f"missing-{ordinal}", {}, "missing", True))

    return Arm(
        name=str(raw.get("arm") or raw.get("name") or fallback_name),
        runs=tuple(runs),
        expected_runs=expected_runs,
        recovery_required=recovery,
    )


def load_arms_file(path: Path, gold_ids: set[str]) -> dict[str, Arm]:
    raw = _load_json(path)
    container = raw.get("arms", raw) if isinstance(raw, dict) else raw
    if isinstance(container, list):
        values = [(str(item.get("arm") or item.get("name") or index), item) for index, item in enumerate(container)]
    elif isinstance(container, dict):
        if "runs" in container or "predictions" in container or "case_results" in container:
            values = [
                (
                    str(container.get("arm") or container.get("name") or path.stem),
                    container,
                )
            ]
        else:
            values = list(container.items())
    else:
        raise ValueError("arms JSON must be a list, mapping, or sealed arm")
    return {name: load_arm(value, gold_ids, fallback_name=name) for name, value in values}


def _confusion(
    gold: Mapping[str, GoldCase],
    predictions: Mapping[str, Prediction],
    case_ids: Iterable[str],
    *,
    cwe: int | None = None,
) -> dict[str, int | float | None]:
    tp = fp = tn = fn = abstain = 0
    selected = list(case_ids)
    for case_id in selected:
        expected = gold[case_id]
        prediction = predictions.get(case_id, Prediction(None, None))
        gold_positive = expected.vulnerable if cwe is None else expected.vulnerable and expected.cwe == cwe
        predicted_positive = prediction.vulnerable
        if cwe is not None and predicted_positive is not None:
            predicted_positive = bool(predicted_positive and prediction.cwe == cwe)
        if prediction.vulnerable is None:
            abstain += 1
            if gold_positive:
                fn += 1
        elif gold_positive and predicted_positive:
            tp += 1
        elif gold_positive:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "n": len(selected),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "abstain": abstain,
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "accuracy_itt": _ratio(tp + tn, len(selected)),
        "coverage": _ratio(len(selected) - abstain, len(selected)),
    }


def _consensus(arm: Arm, gold_ids: Iterable[str]) -> dict[str, Prediction]:
    threshold = arm.expected_runs // 2 + 1
    result: dict[str, Prediction] = {}
    for case_id in gold_ids:
        votes = [run.predictions.get(case_id, Prediction(None, None)) for run in arm.runs]
        true_votes = sum(item.vulnerable is True for item in votes)
        false_votes = sum(item.vulnerable is False for item in votes)
        if max(true_votes, false_votes) < threshold:
            result[case_id] = Prediction(None, None)
            continue
        vulnerable = true_votes > false_votes
        if not vulnerable:
            result[case_id] = Prediction(False, None)
            continue
        cwes = [item.cwe for item in votes if item.vulnerable is True and item.cwe is not None]
        counts = Counter(cwes)
        cwe = counts.most_common(1)[0][0] if counts and counts.most_common(1)[0][1] >= threshold else None
        result[case_id] = Prediction(True, cwe)
    return result


def _score_arm(arm: Arm, gold: Mapping[str, GoldCase], target_cwes: frozenset[int]) -> dict[str, Any]:
    all_ids = sorted(gold)
    scope_ids = [case_id for case_id in all_ids if gold[case_id].cwe in target_cwes]
    rounds: list[dict[str, Any]] = []
    full_runs = operational_runs = 0
    for run in arm.runs:
        complete = len(run.predictions) == len(gold) and all(
            run.predictions[case_id].vulnerable is not None for case_id in gold
        )
        full_runs += int(complete)
        operational_runs += int(run.status in PASSING_STATUSES)
        rounds.append(
            {
                "repetition": run.repetition,
                "status": run.status,
                "synthetic": run.synthetic,
                "complete": complete,
                "overall": _confusion(gold, run.predictions, all_ids),
                "scope": _confusion(gold, run.predictions, scope_ids),
                "per_cwe": {
                    str(cwe): _confusion(gold, run.predictions, all_ids, cwe=cwe) for cwe in sorted(target_cwes)
                },
            }
        )

    consensus = _consensus(arm, all_ids)
    pooled: dict[str, Prediction] = {}
    pooled_gold: dict[str, GoldCase] = {}
    for run_index, run in enumerate(arm.runs):
        for case_id, expected in gold.items():
            pooled_id = f"{run_index}:{case_id}"
            pooled_gold[pooled_id] = GoldCase(pooled_id, expected.vulnerable, expected.cwe, expected.category)
            pooled[pooled_id] = run.predictions.get(case_id, Prediction(None, None))
    pooled_ids = sorted(pooled_gold)
    pooled_scope = [case_id for case_id in pooled_ids if pooled_gold[case_id].cwe in target_cwes]
    return {
        "name": arm.name,
        "expected_runs": arm.expected_runs,
        "scoreable_completion_rate": _ratio(full_runs, arm.expected_runs),
        "operational_completion_rate": _ratio(operational_runs, arm.expected_runs),
        "recovery_required": arm.recovery_required,
        "rounds": rounds,
        "aggregate": {
            "method": "strict-majority-with-abstention",
            "overall": _confusion(gold, consensus, all_ids),
            "scope": _confusion(gold, consensus, scope_ids),
            "per_cwe": {str(cwe): _confusion(gold, consensus, all_ids, cwe=cwe) for cwe in sorted(target_cwes)},
        },
        "pooled": {
            "method": "all-case-run-evaluations",
            "overall": _confusion(pooled_gold, pooled, pooled_ids),
            "scope": _confusion(pooled_gold, pooled, pooled_scope),
        },
        "_consensus": consensus,
    }


def _f1(rows: Sequence[tuple[bool, bool | None]]) -> float:
    tp = fp = fn = 0
    for expected, predicted in rows:
        if expected and predicted is True:
            tp += 1
        elif expected:
            fn += 1
        elif predicted is True:
            fp += 1
    return _ratio(2 * tp, 2 * tp + fp + fn) or 0.0


def _bootstrap_delta(
    gold: Mapping[str, GoldCase],
    baseline: Mapping[str, Prediction],
    candidate: Mapping[str, Prediction],
    case_ids: Sequence[str],
    *,
    draws: int,
    seed: int,
) -> list[float]:
    if draws <= 0:
        return []
    rng = random.Random(seed)  # noqa: S311 - deterministic statistical bootstrap
    deltas: list[float] = []
    for _ in range(draws):
        sample = [case_ids[rng.randrange(len(case_ids))] for _ in case_ids]
        base_rows = [(gold[case_id].vulnerable, baseline[case_id].vulnerable) for case_id in sample]
        candidate_rows = [(gold[case_id].vulnerable, candidate[case_id].vulnerable) for case_id in sample]
        deltas.append(_f1(candidate_rows) - _f1(base_rows))
    deltas.sort()
    return [deltas[int(draws * 0.025)], deltas[min(draws - 1, int(draws * 0.975))]]


def _mcnemar(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if not discordant:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(left_only, right_only) + 1)) / (2**discordant)
    return min(1.0, 2 * tail)


def _paired(
    gold: Mapping[str, GoldCase],
    baseline: Mapping[str, Prediction],
    candidate: Mapping[str, Prediction],
    target_cwes: frozenset[int],
    *,
    draws: int,
    seed: int,
) -> dict[str, Any]:
    all_ids = sorted(gold)
    scope_ids = [case_id for case_id in all_ids if gold[case_id].cwe in target_cwes]
    baseline_correct = candidate_correct = both = neither = 0
    for case_id in scope_ids:
        expected = gold[case_id].vulnerable
        left = baseline[case_id].vulnerable is not None and baseline[case_id].vulnerable == expected
        right = candidate[case_id].vulnerable is not None and candidate[case_id].vulnerable == expected
        both += int(left and right)
        baseline_correct += int(left and not right)
        candidate_correct += int(right and not left)
        neither += int(not left and not right)
    base_overall = _confusion(gold, baseline, all_ids)
    candidate_overall = _confusion(gold, candidate, all_ids)
    base_scope = _confusion(gold, baseline, scope_ids)
    candidate_scope = _confusion(gold, candidate, scope_ids)
    return {
        "overall_delta": {
            key: (candidate_overall[key] or 0.0) - (base_overall[key] or 0.0)
            for key in ("precision", "recall", "f1", "coverage")
        },
        "scope_delta": {
            key: (candidate_scope[key] or 0.0) - (base_scope[key] or 0.0)
            for key in ("precision", "recall", "f1", "coverage")
        },
        "scope_correctness": {
            "both_correct": both,
            "baseline_only_correct": baseline_correct,
            "candidate_only_correct": candidate_correct,
            "neither_correct": neither,
            "mcnemar_exact_two_sided_p": _mcnemar(baseline_correct, candidate_correct),
        },
        "scope_f1_delta_bootstrap_95": _bootstrap_delta(gold, baseline, candidate, scope_ids, draws=draws, seed=seed),
    }


def _decision_rows(raw: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(raw, dict) and isinstance(raw.get("runs"), list):
        for index, run in enumerate(raw["runs"], 1):
            repetition = run.get("repetition", index)
            for item in run.get("unit_decisions", run.get("predictions", [])):
                rows.append(_identity_row(item, repetition))
        return sorted(rows, key=lambda item: (str(item["repetition"]), item["case_id"]))
    if isinstance(raw, dict):
        values = raw.get("unit_decisions", raw.get("predictions"))
        if isinstance(values, list):
            repetition = raw.get("repetition", 1)
            return sorted(
                (_identity_row(item, repetition) for item in values),
                key=lambda item: item["case_id"],
            )
    if isinstance(raw, list):
        return sorted((_identity_row(item, 1) for item in raw), key=lambda item: item["case_id"])
    raise ValueError("frozen replay input must contain predictions or unit_decisions")


def _identity_row(value: Mapping[str, Any], repetition: int | str) -> dict[str, Any]:
    case_id = str(value.get("case_id") or value.get("unit_id") or "")
    if not case_id:
        raise ValueError("frozen replay decision lacks case_id/unit_id")
    return {
        "repetition": repetition,
        "case_id": case_id,
        "vulnerable": value.get("vulnerable", value.get("predicted_vulnerable")),
        "cwe": _safe_int(value.get("cwe", value.get("predicted_cwe"))),
        "decision": value.get("decision", value.get("verdict")),
    }


def compare_frozen_replay(expected_path: Path, runtime_path: Path) -> dict[str, Any]:
    expected = _decision_rows(_load_json(expected_path))
    actual = _decision_rows(_load_json(runtime_path))
    expected_by_key = {(str(item["repetition"]), item["case_id"]): item for item in expected}
    actual_by_key = {(str(item["repetition"]), item["case_id"]): item for item in actual}
    keys = sorted(set(expected_by_key) | set(actual_by_key))
    mismatches = [
        {
            "repetition": key[0],
            "case_id": key[1],
            "expected": expected_by_key.get(key),
            "actual": actual_by_key.get(key),
        }
        for key in keys
        if expected_by_key.get(key) != actual_by_key.get(key)
    ]
    material = json.dumps(actual, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return {
        "semantic_bit_identical": not mismatches,
        "expected_decisions": len(expected),
        "runtime_decisions": len(actual),
        "mismatch_count": len(mismatches),
        "mismatch_examples": mismatches[:10],
        "runtime_decision_sha256": hashlib.sha256(material).hexdigest(),
    }


def evaluate_release_gate(
    gold: Mapping[str, GoldCase],
    baseline: Arm,
    candidate: Arm,
    *,
    target_cwes: frozenset[int] = FOUR_CWE_SCOPE,
    scope_mode: str = "auto",
    bootstrap_draws: int = 5000,
    bootstrap_seed: int = 20260717,
    min_completion_rate: float = 1.0,
    min_coverage: float = 0.98,
    frozen_replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not target_cwes:
        raise ValueError("target CWE scope cannot be empty")
    mode = "same-target-scope" if scope_mode == "auto" and target_cwes == FOUR_CWE_SCOPE else scope_mode
    if mode == "auto":
        mode = "extended-scope"
    if mode not in {"same-target-scope", "extended-scope"}:
        raise ValueError("scope mode must be auto, same-target-scope, or extended-scope")

    baseline_score = _score_arm(baseline, gold, target_cwes)
    candidate_score = _score_arm(candidate, gold, target_cwes)
    baseline_consensus = baseline_score.pop("_consensus")
    candidate_consensus = candidate_score.pop("_consensus")
    paired = _paired(
        gold,
        baseline_consensus,
        candidate_consensus,
        target_cwes,
        draws=bootstrap_draws,
        seed=bootstrap_seed,
    )

    all_positive = sum(item.vulnerable for item in gold.values())
    target_positive = sum(item.vulnerable and item.cwe in target_cwes for item in gold.values())
    target_only_overall_ceiling = _ratio(2 * target_positive, 2 * target_positive + all_positive - target_positive)
    baseline_scope_f1 = baseline_score["aggregate"]["scope"]["f1"] or 0.0
    requested_delta = 0.0 if mode == "same-target-scope" else 0.03
    maximum_scope_delta = 1.0 - baseline_scope_f1

    zero_new_errors = all(
        candidate_score["aggregate"]["per_cwe"][str(cwe)][error]
        <= baseline_score["aggregate"]["per_cwe"][str(cwe)][error]
        for cwe in target_cwes
        for error in ("fp", "fn")
    )
    protected_core_cwes = FOUR_CWE_SCOPE & target_cwes
    protected_core_no_new_errors = all(
        candidate_score["aggregate"]["per_cwe"][str(cwe)][error]
        <= baseline_score["aggregate"]["per_cwe"][str(cwe)][error]
        for cwe in protected_core_cwes
        for error in ("fp", "fn")
    )
    candidate_overall = candidate_score["aggregate"]["overall"]
    baseline_overall = baseline_score["aggregate"]["overall"]
    scope_delta = paired["scope_delta"]["f1"]
    ci = paired["scope_f1_delta_bootstrap_95"]
    checks = {
        "candidate_completion_rate": (candidate_score["scoreable_completion_rate"] or 0.0) >= min_completion_rate,
        "candidate_coverage": (candidate_score["aggregate"]["overall"]["coverage"] or 0.0) >= min_coverage,
        "coverage_not_below_baseline": (candidate_score["aggregate"]["overall"]["coverage"] or 0.0)
        >= (baseline_score["aggregate"]["overall"]["coverage"] or 0.0),
        "recovery_required_zero": candidate_score["recovery_required"] == 0,
        "requested_delta_reachable": maximum_scope_delta + 1e-12 >= requested_delta,
        "frozen_runtime_bit_identical": frozen_replay is None or frozen_replay["semantic_bit_identical"],
    }
    if mode == "same-target-scope":
        checks.update(
            {
                "same_scope_f1_strictly_improves": scope_delta > 0.0,
                "zero_new_target_cwe_errors": zero_new_errors,
            }
        )
    else:
        checks.update(
            {
                "extended_scope_f1_gain_at_least_3pp": scope_delta >= 0.03,
                "paired_bootstrap_95_lower_above_zero": bool(ci) and ci[0] > 0.0,
                "protected_core_no_new_errors": protected_core_no_new_errors,
                "candidate_precision_at_least_95_percent": (candidate_overall["precision"] or 0.0) >= 0.95,
                "candidate_recall_not_below_baseline": (candidate_overall["recall"] or 0.0)
                >= (baseline_overall["recall"] or 0.0),
            }
        )
    blockers = [name for name, passed in checks.items() if not passed]
    return {
        "schema_version": "1.0",
        "protocol": "secmind-v0.7-offline-release-gate",
        "scope": {
            "mode": mode,
            "target_cwes": sorted(target_cwes),
            "all_gold_positives": all_positive,
            "target_gold_positives": target_positive,
            "target_only_overall_f1_ceiling_at_perfect_precision": target_only_overall_ceiling,
            "baseline_scope_f1": baseline_scope_f1,
            "maximum_scope_f1_delta": maximum_scope_delta,
            "required_scope_f1_delta": "> 0" if mode == "same-target-scope" else ">= 0.03",
        },
        "arms": {"baseline": baseline_score, "candidate": candidate_score},
        "paired": paired,
        "frozen_replay": frozen_replay,
        "gate": {"passed": not blockers, "checks": checks, "blockers": blockers},
    }


def _arm_spec(value: str, *, default_name: str) -> tuple[str, Path]:
    if "=" in value:
        name, path = value.split("=", 1)
        if not name or not path:
            raise ValueError("arm specification must be NAME=PATH")
        return name, Path(path)
    return default_name, Path(value)


def _parse_cwes(value: str) -> frozenset[int]:
    try:
        return frozenset(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("CWEs must be comma-separated integers") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate the SecMind v0.7 release gate without network access")
    parser.add_argument("--gold", type=Path, required=True, help="Gold labels JSON")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--arms-json", type=Path, help="JSON containing both arms")
    source.add_argument("--baseline", help="Baseline sealed predictions as NAME=PATH or PATH")
    parser.add_argument("--candidate", help="Candidate sealed predictions as NAME=PATH or PATH")
    parser.add_argument("--baseline-name", default="A", help="Arm key used with --arms-json")
    parser.add_argument("--candidate-name", default="D", help="Arm key used with --arms-json")
    parser.add_argument("--target-cwes", type=_parse_cwes, default=FOUR_CWE_SCOPE)
    parser.add_argument(
        "--scope-mode",
        choices=("auto", "same-target-scope", "extended-scope"),
        default="auto",
    )
    parser.add_argument("--bootstrap-draws", type=int, default=5000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260717)
    parser.add_argument("--min-completion-rate", type=float, default=1.0)
    parser.add_argument("--min-coverage", type=float, default=0.98)
    parser.add_argument("--frozen-receipts", type=Path)
    parser.add_argument("--runtime-replay", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if "--seal-experiment" in values or "--sealed-experiment" in values:
        return abcd_protocol_main(values)
    parser = _parser()
    args = parser.parse_args(values)
    if bool(args.frozen_receipts) != bool(args.runtime_replay):
        parser.error("--frozen-receipts and --runtime-replay must be supplied together")
    if args.baseline and not args.candidate:
        parser.error("--candidate is required with --baseline")

    try:
        gold = load_gold(args.gold)
        if args.arms_json:
            arms = load_arms_file(args.arms_json, set(gold))
            baseline = arms[args.baseline_name]
            candidate = arms[args.candidate_name]
        else:
            baseline_name, baseline_path = _arm_spec(args.baseline, default_name="A")
            candidate_name, candidate_path = _arm_spec(args.candidate, default_name="D")
            baseline = next(iter(load_arms_file(baseline_path, set(gold)).values()))
            candidate = next(iter(load_arms_file(candidate_path, set(gold)).values()))
            baseline = Arm(
                baseline_name,
                baseline.runs,
                baseline.expected_runs,
                baseline.recovery_required,
            )
            candidate = Arm(
                candidate_name,
                candidate.runs,
                candidate.expected_runs,
                candidate.recovery_required,
            )
        frozen = (
            compare_frozen_replay(args.frozen_receipts, args.runtime_replay)
            if args.frozen_receipts and args.runtime_replay
            else None
        )
        report = evaluate_release_gate(
            gold,
            baseline,
            candidate,
            target_cwes=args.target_cwes,
            scope_mode=args.scope_mode,
            bootstrap_draws=args.bootstrap_draws,
            bootstrap_seed=args.bootstrap_seed,
            min_completion_rate=args.min_completion_rate,
            min_coverage=args.min_coverage,
            frozen_replay=frozen,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
