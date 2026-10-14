from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter
from pathlib import Path
from typing import Any

from blind_benchmark_common import canonical_hash, load_manifest, now, prediction_commitment, sha256_file, write_json

TARGET_CWES = frozenset({22, 78, 79, 89})


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _gold(path: Path, case_ids: set[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        rows = csv.reader(line for line in stream if not line.startswith("#"))
        for row in rows:
            if len(row) == 4 and row[0] in case_ids:
                result[row[0]] = {
                    "case_id": row[0],
                    "category": row[1],
                    "vulnerable": row[2].lower() == "true",
                    "cwe": int(row[3]),
                }
    if set(result) != case_ids:
        raise ValueError("gold does not cover the sealed blind sample")
    return result


def _metrics(rows: list[dict[str, Any]], *, target_only: bool = False) -> dict[str, Any]:
    tp = fp = tn = fn = abstain = 0
    for row in rows:
        gold_positive = bool(row["gold_vulnerable"])
        predicted = row["predicted_vulnerable"]
        if target_only:
            gold_positive = gold_positive and row["gold_cwe"] in TARGET_CWES
            predicted = bool(predicted and row["predicted_cwe"] in TARGET_CWES) if predicted is not None else None
        if predicted is None:
            abstain += 1
            if gold_positive:
                fn += 1
            continue
        if gold_positive and predicted:
            tp += 1
        elif gold_positive:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    return {
        "n": len(rows),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "abstain": abstain},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy_intention_to_test": _ratio(tp + tn, len(rows)),
        "balanced_accuracy": (
            round((recall + specificity) / 2, 6) if recall is not None and specificity is not None else None
        ),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "coverage": _ratio(len(rows) - abstain, len(rows)),
    }


def _majority(predictions: list[dict[str, Any]]) -> tuple[bool | None, int | None]:
    votes = [item.get("vulnerable") for item in predictions if item.get("vulnerable") is not None]
    true_votes = sum(value is True for value in votes)
    false_votes = sum(value is False for value in votes)
    if true_votes < 2 and false_votes < 2:
        return None, None
    vulnerable = true_votes > false_votes
    if not vulnerable:
        return False, None
    cwes = [item.get("cwe") for item in predictions if item.get("vulnerable") is True and item.get("cwe")]
    if not cwes:
        return True, None
    cwe, count = Counter(cwes).most_common(1)[0]
    return True, int(str(cwe)) if count >= 2 or len(cwes) == 1 else None


def _score_arm(sealed: dict[str, Any], gold: dict[str, dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    if sealed["input_bundle_sha256"] != manifest["input_bundle_sha256"]:
        raise ValueError("arm used a different input bundle")
    if prediction_commitment(sealed["runs"]) != sealed["prediction_commitment_sha256"]:
        raise ValueError("prediction commitment mismatch")
    by_case: dict[str, list[dict[str, Any]]] = {item["case_id"]: [] for item in manifest["cases"]}
    per_repetition: list[dict[str, Any]] = []
    for run in sealed["runs"]:
        rows: list[dict[str, Any]] = []
        repetition_predictions = {item["case_id"]: item for item in run["predictions"]}
        if set(repetition_predictions) != set(by_case):
            raise ValueError("arm predictions do not match the blind sample")
        for case_id, prediction in repetition_predictions.items():
            by_case[case_id].append(prediction)
            expected = gold[case_id]
            rows.append(
                {
                    "case_id": case_id,
                    "gold_vulnerable": expected["vulnerable"],
                    "gold_cwe": expected["cwe"],
                    "predicted_vulnerable": prediction.get("vulnerable"),
                    "predicted_cwe": prediction.get("cwe"),
                }
            )
        per_repetition.append(
            {
                "repetition": run["repetition"],
                "binary": _metrics(rows),
                "target_cwe_detection": _metrics(rows, target_only=True),
            }
        )

    majority_rows: list[dict[str, Any]] = []
    stable = 0
    evidence_bound = 0
    positive = 0
    cwe_correct = 0
    cwe_denominator = 0
    for case_id, case_predictions in by_case.items():
        vulnerable, cwe = _majority(case_predictions)
        expected = gold[case_id]
        values = [(item.get("vulnerable"), item.get("cwe")) for item in case_predictions]
        stable += int(len(set(values)) == 1)
        if vulnerable:
            positive += 1
            representative = next(item for item in case_predictions if item.get("vulnerable") is True)
            evidence_bound += int(bool(representative.get("evidence_path") and representative.get("evidence_sha256")))
        if vulnerable and expected["vulnerable"]:
            cwe_denominator += 1
            cwe_correct += int(cwe == expected["cwe"])
        majority_rows.append(
            {
                "case_id": case_id,
                "category": expected["category"],
                "gold_vulnerable": expected["vulnerable"],
                "gold_cwe": expected["cwe"],
                "predicted_vulnerable": vulnerable,
                "predicted_cwe": cwe,
                "stable_three_runs": len(set(values)) == 1,
                "per_run": values,
                "correct_binary": vulnerable is not None and vulnerable == expected["vulnerable"],
                "correct_joint": (
                    vulnerable is False if not expected["vulnerable"] else vulnerable is True and cwe == expected["cwe"]
                ),
            }
        )
    return {
        "arm": sealed["arm"],
        "prediction_commitment_sha256": sealed["prediction_commitment_sha256"],
        "majority_binary": _metrics(majority_rows),
        "majority_target_cwe_detection": _metrics(majority_rows, target_only=True),
        "cwe_accuracy_among_detected_gold_positives": _ratio(cwe_correct, cwe_denominator),
        "joint_accuracy_intention_to_test": _ratio(
            sum(bool(item["correct_joint"]) for item in majority_rows), len(majority_rows)
        ),
        "three_run_exact_stability": _ratio(stable, len(majority_rows)),
        "finding_evidence_binding": _ratio(evidence_bound, positive),
        "per_repetition": per_repetition,
        "usage": sealed.get("usage", {}),
        "case_results": majority_rows,
    }


def _exact_mcnemar(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> dict[str, Any]:
    right_by_id = {item["case_id"]: item for item in right}
    n10 = n01 = 0
    for item in left:
        other = right_by_id[item["case_id"]]
        left_correct = bool(item["correct_binary"])
        right_correct = bool(other["correct_binary"])
        n10 += int(left_correct and not right_correct)
        n01 += int(not left_correct and right_correct)
    discordant = n10 + n01
    if not discordant:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, k) for k in range(0, min(n10, n01) + 1)) / (2**discordant)
        p_value = min(1.0, 2 * tail)
    return {"left_only_correct": n10, "right_only_correct": n01, "exact_p_value": round(p_value, 8)}


def _bootstrap_f1_delta(
    left: list[dict[str, Any]], right: list[dict[str, Any]], *, seed: int = 20260715, draws: int = 5000
) -> list[float]:
    rng = random.Random(seed)  # noqa: S311 - reproducible statistical bootstrap, not cryptography
    right_by_id = {item["case_id"]: item for item in right}
    deltas: list[float] = []
    for _ in range(draws):
        sample = [left[rng.randrange(len(left))] for _ in left]
        left_f1 = _metrics(sample)["f1"] or 0.0
        matched = [right_by_id[item["case_id"]] for item in sample]
        right_f1 = _metrics(matched)["f1"] or 0.0
        deltas.append(left_f1 - right_f1)
    deltas.sort()
    return [round(deltas[int(draws * 0.025)], 6), round(deltas[int(draws * 0.975)], 6)]


def score(benchmark: Path, input_root: Path, arm_dirs: list[Path], output: Path) -> None:
    manifest = load_manifest(input_root / "blind-manifest.json")
    case_ids = {item["case_id"] for item in manifest["cases"]}
    gold_path = benchmark / "expectedresults-1.2.csv"
    gold = _gold(gold_path, case_ids)
    scored: list[dict[str, Any]] = []
    for arm_dir in arm_dirs:
        sealed_path = arm_dir / "raw" / "sealed-predictions.json"
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        arm_score = _score_arm(sealed, gold, manifest)
        scored.append(arm_score)
        write_json(output / "arms" / f"{sealed['arm']}.json", arm_score)

    comparisons: list[dict[str, Any]] = []
    for left_index in range(len(scored)):
        for right_index in range(left_index + 1, len(scored)):
            left, right = scored[left_index], scored[right_index]
            comparison = {
                "left": left["arm"],
                "right": right["arm"],
                **_exact_mcnemar(left["case_results"], right["case_results"]),
                "paired_bootstrap_f1_delta_95ci": _bootstrap_f1_delta(left["case_results"], right["case_results"]),
            }
            comparisons.append(comparison)
    write_json(
        output / "metrics.json",
        {
            "schema_version": "1.0",
            "scored_at": now(),
            "input_bundle_sha256": manifest["input_bundle_sha256"],
            "gold_sha256": sha256_file(gold_path),
            "gold_loaded_only_by_scorer": True,
            "target_cwes": sorted(TARGET_CWES),
            "arms": [{key: value for key, value in item.items() if key != "case_results"} for item in scored],
            "paired_comparisons": comparisons,
        },
    )
    write_json(output / "comparison.json", {"comparisons": comparisons})
    write_json(
        output / "score-commitment.json",
        {
            "metrics_sha256": sha256_file(output / "metrics.json"),
            "comparison_sha256": sha256_file(output / "comparison.json"),
            "arm_score_hashes": {item["arm"]: canonical_hash(item["case_results"]) for item in scored},
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Score sealed blind predictions in a separate gold-reading process")
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--arm-dir", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    score(
        args.benchmark_root.resolve(),
        args.input_dir.resolve(),
        [path.resolve() for path in args.arm_dir],
        args.output_dir.resolve(),
    )


if __name__ == "__main__":
    main()
