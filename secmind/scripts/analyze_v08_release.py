from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _number(value: Any, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise SystemExit(f"missing numeric release metric: {label}")
    number = float(value)
    if not math.isfinite(number):
        raise SystemExit(f"non-finite release metric: {label}")
    return number


def _ratio(candidate: float, baseline: float) -> float | None:
    if baseline == 0:
        return 1.0 if candidate == 0 else None
    return candidate / baseline


def _check(
    checks: list[dict[str, Any]],
    name: str,
    passed: bool,
    *,
    actual: Any,
    requirement: str,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "actual": actual,
            "requirement": requirement,
        }
    )


def analyze_release(
    scores: dict[str, Any],
    *,
    baseline_arm: str,
    candidate_arm: str,
    min_overall_delta: float = 0.0,
    min_exact_f1_delta: float = 0.0,
    max_provider_request_ratio: float = 1.2,
    max_token_ratio: float = 1.25,
    max_duration_ratio: float = 1.25,
) -> dict[str, Any]:
    if scores.get("protocol") != "secmind-v08-release-score-v1" or not scores.get("offline_only"):
        raise SystemExit("release analysis requires the offline v0.8 score protocol")
    arms = scores.get("arms") or {}
    if baseline_arm not in arms or candidate_arm not in arms:
        raise SystemExit(f"missing release arms: {baseline_arm}/{candidate_arm}")

    baseline = arms[baseline_arm]["aggregate"]
    candidate = arms[candidate_arm]["aggregate"]
    baseline_exact = baseline["exact_cwe"]
    candidate_exact = candidate["exact_cwe"]
    baseline_usage = baseline["usage"]
    candidate_usage = candidate["usage"]

    overall_delta = _number(candidate["overall_score"], "candidate overall") - _number(
        baseline["overall_score"], "baseline overall"
    )
    exact_f1_delta = _number(candidate_exact["f1"], "candidate exact-CWE F1") - _number(
        baseline_exact["f1"], "baseline exact-CWE F1"
    )
    provider_ratio = _ratio(
        _number(candidate_usage["provider_requests"], "candidate provider requests"),
        _number(baseline_usage["provider_requests"], "baseline provider requests"),
    )
    token_ratio = _ratio(
        _number(candidate_usage["total_tokens"], "candidate total tokens"),
        _number(baseline_usage["total_tokens"], "baseline total tokens"),
    )
    duration_ratio = _ratio(
        _number(candidate_usage["summed_task_duration_ms"], "candidate duration"),
        _number(baseline_usage["summed_task_duration_ms"], "baseline duration"),
    )

    checks: list[dict[str, Any]] = []
    _check(
        checks,
        "overall_score_gain",
        overall_delta > min_overall_delta,
        actual=round(overall_delta, 6),
        requirement=f"> {min_overall_delta}",
    )
    _check(
        checks,
        "exact_cwe_f1_gain",
        exact_f1_delta > min_exact_f1_delta,
        actual=round(exact_f1_delta, 6),
        requirement=f"> {min_exact_f1_delta}",
    )
    _check(
        checks,
        "exact_cwe_true_positives",
        int(candidate_exact["tp"]) > int(baseline_exact["tp"]),
        actual={"baseline": baseline_exact["tp"], "candidate": candidate_exact["tp"]},
        requirement="candidate > baseline",
    )
    _check(
        checks,
        "exact_cwe_false_positives",
        int(candidate_exact["fp"]) <= int(baseline_exact["fp"]),
        actual={"baseline": baseline_exact["fp"], "candidate": candidate_exact["fp"]},
        requirement="candidate <= baseline",
    )
    _check(
        checks,
        "exact_cwe_recall",
        _number(candidate_exact["recall"], "candidate exact-CWE recall")
        >= _number(baseline_exact["recall"], "baseline exact-CWE recall"),
        actual={"baseline": baseline_exact["recall"], "candidate": candidate_exact["recall"]},
        requirement="candidate >= baseline",
    )
    for metric in ("timeout_rate", "operational_failure_rate"):
        _check(
            checks,
            metric,
            _number(candidate[metric], f"candidate {metric}") == 0,
            actual=candidate[metric],
            requirement="== 0",
        )
    for metric in (
        "ledger_valid_rate",
        "finding_evidence_completeness",
        "baseline_chain_complete_rate",
        "baseline_chain_consistent_rate",
        "primary_preserved_rate",
    ):
        _check(
            checks,
            metric,
            _number(candidate[metric], f"candidate {metric}") == 1,
            actual=candidate[metric],
            requirement="== 1",
        )
    for name, actual, maximum in (
        ("provider_request_ratio", provider_ratio, max_provider_request_ratio),
        ("total_token_ratio", token_ratio, max_token_ratio),
        ("duration_ratio", duration_ratio, max_duration_ratio),
    ):
        _check(
            checks,
            name,
            actual is not None and actual <= maximum,
            actual=None if actual is None else round(actual, 6),
            requirement=f"<= {maximum}",
        )

    return {
        "schema_version": "1.0",
        "protocol": "secmind-v08-release-gate-v1",
        "offline_only": True,
        "provider_requests_by_analyzer": 0,
        "baseline_arm": baseline_arm,
        "candidate_arm": candidate_arm,
        "cohort": {
            "dataset_version": scores.get("dataset_version"),
            "case_count": scores.get("case_count"),
            "repetitions": scores.get("repetitions"),
        },
        "deltas": {
            "overall_score": round(overall_delta, 6),
            "exact_cwe_f1": round(exact_f1_delta, 6),
            "exact_cwe_tp": int(candidate_exact["tp"]) - int(baseline_exact["tp"]),
            "exact_cwe_fp": int(candidate_exact["fp"]) - int(baseline_exact["fp"]),
            "exact_cwe_fn": int(candidate_exact["fn"]) - int(baseline_exact["fn"]),
        },
        "cost_ratios": {
            "provider_requests": provider_ratio,
            "total_tokens": token_ratio,
            "summed_task_duration_ms": duration_ratio,
        },
        "checks": checks,
        "failed_checks": [item["name"] for item in checks if not item["passed"]],
        "release_gate_passed": all(item["passed"] for item in checks),
        "limitations": [
            "This gate compares only the sealed cohort and does not estimate performance outside it.",
            "Duration is summed task latency, not wall-clock throughput.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline v0.7.1 to v0.8 release-gain gate")
    parser.add_argument("--scores", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-arm", default="v071")
    parser.add_argument("--candidate-arm", default="v080")
    parser.add_argument("--min-overall-delta", type=float, default=0.0)
    parser.add_argument("--min-exact-f1-delta", type=float, default=0.0)
    parser.add_argument("--max-provider-request-ratio", type=float, default=1.2)
    parser.add_argument("--max-token-ratio", type=float, default=1.25)
    parser.add_argument("--max-duration-ratio", type=float, default=1.25)
    parser.add_argument("--enforce", action="store_true", help="Exit non-zero when any release check fails")
    args = parser.parse_args()

    for name in (
        "max_provider_request_ratio",
        "max_token_ratio",
        "max_duration_ratio",
    ):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    scores_path = args.scores.resolve()
    scores = json.loads(scores_path.read_text(encoding="utf-8"))
    analysis = analyze_release(
        scores,
        baseline_arm=args.baseline_arm,
        candidate_arm=args.candidate_arm,
        min_overall_delta=args.min_overall_delta,
        min_exact_f1_delta=args.min_exact_f1_delta,
        max_provider_request_ratio=args.max_provider_request_ratio,
        max_token_ratio=args.max_token_ratio,
        max_duration_ratio=args.max_duration_ratio,
    )
    analysis["provenance"] = {
        "scores_sha256": file_sha256(scores_path),
        "scorer_sha256": scores.get("scorer_sha256"),
        "analyzer_sha256": file_sha256(Path(__file__).resolve()),
    }
    write_json(args.output.resolve(), analysis)
    print(json.dumps(analysis, ensure_ascii=False, indent=2))
    if args.enforce and not analysis["release_gate_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
