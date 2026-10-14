from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from secmind_dev.v07_evaluation import (
    EXTENDED_CWES,
    V07EvaluationError,
    canonical_sha256,
    evaluate_abcd_protocol,
    load_gold,
    score_files,
    seal_experiment,
    validate_sealed_experiment,
)


def _digest(value: str) -> str:
    return canonical_sha256({"value": value})


def _gold(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    cases: dict[str, Any] = {}
    for cwe in sorted(EXTENDED_CWES):
        cases[f"p-{cwe}"] = {"gold_vulnerable": True, "cwe": cwe}
        cases[f"n-{cwe}"] = {"gold_vulnerable": False, "cwe": cwe}
        cases[f"p-{cwe}-b"] = {"gold_vulnerable": True, "cwe": cwe}
        cases[f"n-{cwe}-b"] = {"gold_vulnerable": False, "cwe": cwe}
    path = tmp_path / "gold.json"
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path, cases


def _prediction(expected: MappingLike, *, missed: bool = False) -> dict[str, Any]:
    vulnerable = bool(expected["gold_vulnerable"]) and not missed
    return {
        "vulnerable": vulnerable,
        "cwe": expected["cwe"] if vulnerable else None,
    }


MappingLike = dict[str, Any]


def _identity(case_id: str, repetition: int) -> dict[str, Any]:
    return {
        "input_manifest_digest": _digest("manifest"),
        "audit_profile_digest": _digest("extended-profile"),
        "unit_id": case_id,
        "primary_source_digest": _digest(f"source:{case_id}"),
        "support_context_digests": [_digest("support")],
        "model_catalog_digest": _digest("catalog"),
        "model_id": "approved-5.4-or-lower",
        "base_url_policy_id": "competition-gateway",
        "prompt_template_version": "direct-v7",
        "response_schema_version": "1.0",
        "temperature": 0,
        "seed": repetition,
        "max_input_tokens": 32768,
        "max_output_tokens": 4096,
        "timeout": 120,
        "retry_policy": {"attempts": 1, "repair": "none"},
        "request_digest": _digest(f"request:{case_id}:{repetition}"),
        "system_prompt_digest": _digest("system:direct-v7"),
        "user_prompt_digest": _digest(f"user:{case_id}"),
        "reasoning_effort": "medium",
        "thinking_mode": "bounded",
    }


def _experiment(cases: dict[str, Any]) -> dict[str, Any]:
    arms: dict[str, Any] = {}
    missed = {"p-327", "p-327-b", "p-330", "p-330-b"}
    for arm_name in ("A", "B", "C", "D"):
        runs = []
        for repetition in (1, 2, 3):
            records = []
            for case_id, expected in cases.items():
                baseline = _prediction(expected, missed=case_id in missed)
                candidate = _prediction(expected)
                prediction = baseline if arm_name in {"A", "B"} else candidate
                record: dict[str, Any] = {
                    "case_id": case_id,
                    "prediction": prediction,
                    "baseline_prediction": baseline,
                    "public_prediction": baseline if arm_name == "D" else prediction,
                    "pair_identity": _identity(case_id, repetition),
                    "provider_receipt_commitment_sha256": _digest(f"receipt:{repetition}:{case_id}"),
                    "augmentation_status": "completed",
                }
                if arm_name in {"C", "D"} and case_id in missed:
                    record["patches"] = [
                        {
                            "patch_key": "configuration:secure-random",
                            "patch_kind": "configuration",
                            "cwe": expected["cwe"],
                            "evidence_digest": _digest(f"evidence:{case_id}"),
                            "rule_bundle_digest": _digest("rules"),
                            "parser_digest": _digest("parser"),
                        }
                    ]
                records.append(record)
            runs.append(
                {
                    "repetition": repetition,
                    "execution_id": f"{arm_name.lower()}-execution-{repetition}",
                    "status": "completed",
                    "records": records,
                }
            )
        arms[arm_name] = {"runs": runs}
    return {
        "experiment_id": "v07-offline-paired",
        "expected_repetitions": 3,
        "target_cwes": sorted(EXTENDED_CWES),
        "arms": arms,
    }


def _score(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    gold_path, cases = _gold(tmp_path)
    sealed = seal_experiment(_experiment(cases))
    report = evaluate_abcd_protocol(sealed, load_gold(gold_path), bootstrap_draws=1000)
    return sealed, report, gold_path


def test_sealing_rejects_gold_and_detects_post_commitment_mutation(
    tmp_path: Path,
) -> None:
    _, cases = _gold(tmp_path)
    experiment = _experiment(cases)
    experiment["gold_labels"] = {"p-22": True}
    with pytest.raises(V07EvaluationError, match="Gold"):
        seal_experiment(experiment)

    experiment.pop("gold_labels")
    sealed = seal_experiment(experiment)
    validate_sealed_experiment(sealed)
    sealed["arms"]["A"]["runs"][0]["records"][0]["prediction"]["vulnerable"] = False
    with pytest.raises(V07EvaluationError, match="commitment mismatch"):
        validate_sealed_experiment(sealed)


def test_abcd_protocol_passes_pair_patch_and_superiority_gates(tmp_path: Path) -> None:
    _, report, _ = _score(tmp_path)

    assert report["highest_passed_gate"] == 3
    assert all(report["gates"][f"gate_{number}"]["passed"] for number in range(4))
    assert report["provider_requests_made_by_scorer"] == 0
    assert report["gold_isolation"]["prediction_commitment_verified_before_scoring"] is True
    metrics = report["arms"]["D"]["aggregate"]
    assert metrics["overall_binary_f1"] == 1.0
    assert metrics["target_cwe_f1"] == 1.0
    assert metrics["coverage"] == 1.0
    assert metrics["effective_f1"] == 1.0
    patch = report["patches"][0]
    assert patch["tp_fixed"] == 12
    assert patch["fp_introduced"] == 0
    assert patch["fn_introduced"] == 0
    assert patch["qualified"] is True
    assert all(item["no_negative_gain"] for item in report["paired"]["run_deltas"])


@pytest.mark.parametrize("field", ["pair_identity", "receipt"])
def test_gate_zero_rejects_any_pair_or_receipt_drift(tmp_path: Path, field: str) -> None:
    gold_path, cases = _gold(tmp_path)
    experiment = _experiment(cases)
    record = experiment["arms"]["B"]["runs"][0]["records"][0]
    if field == "pair_identity":
        record["pair_identity"]["max_output_tokens"] = 2048
    else:
        record["provider_receipt_commitment_sha256"] = _digest("different")
    report = evaluate_abcd_protocol(seal_experiment(experiment), load_gold(gold_path), bootstrap_draws=20)

    assert report["gates"]["gate_0"]["passed"] is False
    check = "pair_identity_all_fields_match" if field == "pair_identity" else "provider_receipt_commitments_match"
    assert report["gates"]["gate_0"]["checks"][check] is False
    assert report["highest_passed_gate"] == -1


def test_missing_run_is_scored_as_failure_instead_of_filtered(tmp_path: Path) -> None:
    gold_path, cases = _gold(tmp_path)
    experiment = _experiment(cases)
    experiment["arms"]["D"]["runs"].pop()
    report = evaluate_abcd_protocol(seal_experiment(experiment), load_gold(gold_path), bootstrap_draws=20)

    candidate = report["arms"]["D"]
    assert candidate["completion_rate"] == pytest.approx(2 / 3)
    assert candidate["aggregate"]["coverage"] == pytest.approx(2 / 3)
    assert candidate["aggregate"]["missing_as_failure"] == len(cases)
    assert candidate["aggregate"]["effective_f1"] < candidate["aggregate"]["overall_binary_f1"]
    assert report["gates"]["gate_3"]["checks"]["missing_runs_zero"] is False
    assert report["canary_superiority_passed"] is False


def test_one_negative_repetition_fails_three_run_non_regression(tmp_path: Path) -> None:
    gold_path, cases = _gold(tmp_path)
    experiment = _experiment(cases)
    for arm_name in ("C", "D"):
        for case_id in ("p-327", "p-327-b", "p-330", "p-330-b"):
            record = next(
                item for item in experiment["arms"][arm_name]["runs"][1]["records"] if item["case_id"] == case_id
            )
            record["prediction"] = copy.deepcopy(record["baseline_prediction"])
            record.pop("patches")
    bad = next(record for record in experiment["arms"]["C"]["runs"][1]["records"] if record["case_id"] == "n-22")
    bad["prediction"] = {"vulnerable": True, "cwe": 22}
    bad["patches"] = [
        {
            "patch_key": "bad:taint",
            "patch_kind": "taint",
            "cwe": 22,
            "evidence_digest": _digest("bad-evidence"),
            "rule_bundle_digest": _digest("rules"),
            "parser_digest": _digest("parser"),
        }
    ]
    d_bad = next(record for record in experiment["arms"]["D"]["runs"][1]["records"] if record["case_id"] == "n-22")
    d_bad["prediction"] = copy.deepcopy(bad["prediction"])
    d_bad["patches"] = copy.deepcopy(bad["patches"])
    report = evaluate_abcd_protocol(seal_experiment(experiment), load_gold(gold_path), bootstrap_draws=50)

    assert report["paired"]["run_deltas"][1]["no_negative_gain"] is False
    assert report["gates"]["gate_3"]["checks"]["three_runs_no_negative_gain"] is False
    bad_patch = next(item for item in report["patches"] if item["patch_key"] == "bad:taint")
    assert bad_patch["tp_fixed"] == 0
    assert bad_patch["fp_introduced"] == 1


def test_score_files_checks_commitment_before_opening_gold(tmp_path: Path) -> None:
    _, cases = _gold(tmp_path)
    sealed = seal_experiment(_experiment(cases))
    sealed["arms"]["A"]["runs"][0]["status"] = "tampered"
    sealed_path = tmp_path / "sealed.json"
    sealed_path.write_text(json.dumps(sealed), encoding="utf-8")

    with pytest.raises(V07EvaluationError, match="commitment mismatch"):
        score_files(sealed_path, tmp_path / "gold-does-not-exist.json")


def test_cli_seals_without_gold_then_scores_committed_payload(tmp_path: Path) -> None:
    from secmind_dev.v07_evaluation import main

    gold_path, cases = _gold(tmp_path)
    raw_path = tmp_path / "raw.json"
    sealed_path = tmp_path / "sealed.json"
    report_path = tmp_path / "report.json"
    raw_path.write_text(json.dumps(_experiment(cases)), encoding="utf-8")

    assert main(["--seal-experiment", str(raw_path), "--output", str(sealed_path)]) == 0
    assert (
        main(
            [
                "--sealed-experiment",
                str(sealed_path),
                "--gold",
                str(gold_path),
                "--bootstrap-draws",
                "1000",
                "--output",
                str(report_path),
            ]
        )
        == 0
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["canary_superiority_passed"] is True


def test_compatibility_script_delegates_new_abcd_cli(tmp_path: Path) -> None:
    _, cases = _gold(tmp_path)
    raw_path = tmp_path / "raw.json"
    sealed_path = tmp_path / "sealed.json"
    raw_path.write_text(json.dumps(_experiment(cases)), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(
        "evaluate_v07_release_gate_abcd_test",
        Path("scripts/evaluate_v07_release_gate.py"),
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    assert module.main(["--seal-experiment", str(raw_path), "--output", str(sealed_path)]) == 0
    validate_sealed_experiment(json.loads(sealed_path.read_text(encoding="utf-8")))


def test_wrong_cwe_is_not_counted_as_a_true_positive(tmp_path: Path) -> None:
    gold_path, cases = _gold(tmp_path)
    experiment = _experiment(cases)
    for arm_name in ("C", "D"):
        record = next(item for item in experiment["arms"][arm_name]["runs"][0]["records"] if item["case_id"] == "p-327")
        record["prediction"] = {"vulnerable": True, "cwe": 328}
    report = evaluate_abcd_protocol(seal_experiment(experiment), load_gold(gold_path), bootstrap_draws=1000)

    metrics = report["arms"]["D"]["rounds"][0]
    assert metrics["overall_binary_f1"] == 1.0
    assert metrics["exact_cwe_f1"] < 1.0
    patch = next(item for item in report["patches"] if item["patch_key"] == "configuration:secure-random")
    assert patch["cwe_misclassified"] == 1
    assert patch["qualified"] is False
