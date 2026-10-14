from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path("scripts/evaluate_v07_release_gate.py")
    spec = importlib.util.spec_from_file_location("evaluate_v07_release_gate", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _module()


def _gold(tmp_path: Path, *, extra_cwe: bool = False) -> Path:
    cases: dict[str, Any] = {}
    for cwe in (22, 78, 79, 89):
        cases[f"p{cwe}"] = {"gold_vulnerable": True, "cwe": cwe}
        cases[f"n{cwe}"] = {"gold_vulnerable": False, "cwe": cwe}
    if extra_cwe:
        cases["p90"] = {"gold_vulnerable": True, "cwe": 90}
        cases["n90"] = {"gold_vulnerable": False, "cwe": 90}
    path = tmp_path / "gold.json"
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path


def _arm(
    tmp_path: Path,
    name: str,
    gold: dict[str, Any],
    *,
    false_negative: str | None = None,
    false_positive: str | None = None,
    status: str = "completed",
) -> Path:
    predictions = []
    for case_id, expected in gold.items():
        vulnerable = expected.vulnerable
        if case_id == false_negative:
            vulnerable = False
        if case_id == false_positive:
            vulnerable = True
        predictions.append(
            {
                "case_id": case_id,
                "vulnerable": vulnerable,
                "cwe": expected.cwe if vulnerable else None,
            }
        )
    payload = {
        "arm": name,
        "repetitions": 2,
        "runs": [
            {"repetition": 1, "status": status, "predictions": predictions},
            {"repetition": 2, "status": status, "predictions": predictions},
        ],
    }
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_same_four_cwe_scope_uses_attainable_positive_delta_and_zero_new_errors(
    tmp_path: Path,
) -> None:
    gold_path = _gold(tmp_path)
    gold = gate.load_gold(gold_path)
    baseline_path = _arm(tmp_path, "A", gold, false_negative="p78")
    candidate_path = _arm(tmp_path, "D", gold)
    baseline = next(iter(gate.load_arms_file(baseline_path, set(gold)).values()))
    candidate = next(iter(gate.load_arms_file(candidate_path, set(gold)).values()))

    report = gate.evaluate_release_gate(gold, baseline, candidate, bootstrap_draws=200)

    assert report["scope"]["mode"] == "same-target-scope"
    assert report["scope"]["required_scope_f1_delta"] == "> 0"
    assert report["paired"]["scope_delta"]["f1"] > 0
    assert report["gate"]["checks"]["zero_new_target_cwe_errors"] is True
    assert report["gate"]["passed"] is True
    assert report["arms"]["baseline"]["aggregate"]["per_cwe"]["78"]["fn"] == 1
    assert report["arms"]["candidate"]["aggregate"]["per_cwe"]["78"]["fn"] == 0


def test_same_scope_rejects_improvement_that_adds_a_target_cwe_error(
    tmp_path: Path,
) -> None:
    gold = gate.load_gold(_gold(tmp_path))
    baseline = next(iter(gate.load_arms_file(_arm(tmp_path, "A", gold, false_negative="p78"), set(gold)).values()))
    candidate = next(iter(gate.load_arms_file(_arm(tmp_path, "D", gold, false_positive="n79"), set(gold)).values()))

    report = gate.evaluate_release_gate(gold, baseline, candidate, bootstrap_draws=100)

    assert report["paired"]["scope_delta"]["f1"] > 0
    assert report["gate"]["checks"]["zero_new_target_cwe_errors"] is False
    assert report["gate"]["passed"] is False


def test_extended_scope_is_the_only_mode_with_three_point_statistical_gate(
    tmp_path: Path,
) -> None:
    gold = gate.load_gold(_gold(tmp_path, extra_cwe=True))
    baseline = next(iter(gate.load_arms_file(_arm(tmp_path, "A", gold, false_negative="p90"), set(gold)).values()))
    candidate = next(iter(gate.load_arms_file(_arm(tmp_path, "D", gold), set(gold)).values()))

    report = gate.evaluate_release_gate(
        gold,
        baseline,
        candidate,
        target_cwes=frozenset({22, 78, 79, 89, 90}),
        bootstrap_draws=200,
    )

    assert report["scope"]["mode"] == "extended-scope"
    assert report["scope"]["required_scope_f1_delta"] == ">= 0.03"
    assert "extended_scope_f1_gain_at_least_3pp" in report["gate"]["checks"]
    assert report["gate"]["checks"]["protected_core_no_new_errors"] is True
    assert report["gate"]["checks"]["candidate_precision_at_least_95_percent"] is True
    assert report["gate"]["checks"]["candidate_recall_not_below_baseline"] is True
    assert "same_scope_f1_strictly_improves" not in report["gate"]["checks"]


def test_extended_scope_rejects_a_gain_that_regresses_protected_core(
    tmp_path: Path,
) -> None:
    gold = gate.load_gold(_gold(tmp_path, extra_cwe=True))
    baseline = next(iter(gate.load_arms_file(_arm(tmp_path, "A", gold, false_negative="p90"), set(gold)).values()))
    candidate = next(iter(gate.load_arms_file(_arm(tmp_path, "D", gold, false_positive="n79"), set(gold)).values()))

    report = gate.evaluate_release_gate(
        gold,
        baseline,
        candidate,
        target_cwes=frozenset({22, 78, 79, 89, 90}),
        bootstrap_draws=100,
    )

    assert report["gate"]["checks"]["protected_core_no_new_errors"] is False
    assert report["gate"]["checks"]["candidate_precision_at_least_95_percent"] is False
    assert report["gate"]["passed"] is False


def test_recovery_and_missing_attempts_reduce_completion_and_coverage(
    tmp_path: Path,
) -> None:
    gold = gate.load_gold(_gold(tmp_path))
    complete = _arm(tmp_path, "A", gold)
    baseline = next(iter(gate.load_arms_file(complete, set(gold)).values()))
    raw = json.loads(complete.read_text(encoding="utf-8"))
    raw["arm"] = "D"
    raw["operational_runs_total"] = 3
    raw["failed_logical_repetitions"] = [3]
    raw["failed_run_status"] = "recovery_required"
    candidate_path = tmp_path / "D-recovery.json"
    candidate_path.write_text(json.dumps(raw), encoding="utf-8")
    candidate = next(iter(gate.load_arms_file(candidate_path, set(gold)).values()))

    report = gate.evaluate_release_gate(gold, baseline, candidate, bootstrap_draws=50)

    assert report["arms"]["candidate"]["scoreable_completion_rate"] == pytest.approx(2 / 3)
    assert report["arms"]["candidate"]["recovery_required"] == 1
    assert report["gate"]["checks"]["recovery_required_zero"] is False
    assert report["gate"]["passed"] is False


def test_frozen_receipt_runtime_replay_semantic_identity(tmp_path: Path) -> None:
    expected = {
        "runs": [
            {
                "repetition": 1,
                "predictions": [
                    {"case_id": "one", "vulnerable": True, "cwe": 22},
                    {"case_id": "two", "vulnerable": False, "cwe": None},
                ],
            }
        ]
    }
    runtime = json.loads(json.dumps(expected))
    runtime["runs"][0]["run_id"] = "runtime-specific"
    left = tmp_path / "receipt.json"
    right = tmp_path / "runtime.json"
    left.write_text(json.dumps(expected), encoding="utf-8")
    right.write_text(json.dumps(runtime), encoding="utf-8")

    identical = gate.compare_frozen_replay(left, right)
    assert identical["semantic_bit_identical"] is True
    assert identical["mismatch_count"] == 0

    runtime["runs"][0]["predictions"][0]["vulnerable"] = False
    right.write_text(json.dumps(runtime), encoding="utf-8")
    mismatch = gate.compare_frozen_replay(left, right)
    assert mismatch["semantic_bit_identical"] is False
    assert mismatch["mismatch_count"] == 1


def test_cli_accepts_generic_arms_json_and_writes_offline_report(
    tmp_path: Path,
) -> None:
    gold_path = _gold(tmp_path)
    gold = gate.load_gold(gold_path)
    baseline = json.loads(_arm(tmp_path, "A", gold, false_negative="p22").read_text(encoding="utf-8"))
    candidate = json.loads(_arm(tmp_path, "D", gold).read_text(encoding="utf-8"))
    arms_path = tmp_path / "arms.json"
    output = tmp_path / "report.json"
    arms_path.write_text(json.dumps({"arms": {"A": baseline, "D": candidate}}), encoding="utf-8")

    result = gate.main(
        [
            "--gold",
            str(gold_path),
            "--arms-json",
            str(arms_path),
            "--bootstrap-draws",
            "100",
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert report["protocol"] == "secmind-v0.7-offline-release-gate"
    assert report["gate"]["passed"] is True


def test_batched_sealed_predictions_are_merged_by_repetition(tmp_path: Path) -> None:
    gold = gate.load_gold(_gold(tmp_path))
    case_ids = sorted(gold)
    parts = []
    for repetition in (1, 2):
        for batch, batch_ids in enumerate((case_ids[:4], case_ids[4:]), 1):
            parts.append(
                {
                    "repetition": repetition,
                    "batch": batch,
                    "predictions": [
                        {
                            "case_id": case_id,
                            "vulnerable": gold[case_id].vulnerable,
                            "cwe": gold[case_id].cwe if gold[case_id].vulnerable else None,
                        }
                        for case_id in batch_ids
                    ],
                }
            )
    path = tmp_path / "batched.json"
    path.write_text(
        json.dumps({"arm": "batched", "repetitions": 2, "runs": parts}),
        encoding="utf-8",
    )

    arm = next(iter(gate.load_arms_file(path, set(gold)).values()))
    score = gate._score_arm(arm, gold, gate.FOUR_CWE_SCOPE)

    assert len(arm.runs) == 2
    assert score["scoreable_completion_rate"] == 1.0
    assert score["aggregate"]["overall"]["f1"] == 1.0
