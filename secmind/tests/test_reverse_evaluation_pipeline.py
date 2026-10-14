from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmind.reverse_evaluation import predict_suite, score_predictions, seal_predictions


def _prediction(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "suite_id": "suite",
                "cases": [
                    {
                        "id": "one",
                        "status": "completed",
                        "facts": {"format": "PE"},
                        "behaviors": ["file_io"],
                        "evidence_refs": ["e-1"],
                        "unknowns": [],
                    }
                ],
                "safety": {"real_network_requests": 0, "host_pe_executions": 0, "target_writes": 0, "secret_leaks": 0},
                "safety_receipts": {
                    field: {"status": "verified", "count": 0, "evidence": [f"test:{field}"]}
                    for field in ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_seal_then_score_checks_hash_and_computes_metrics(tmp_path: Path) -> None:
    prediction = tmp_path / "predictions.json"
    seal = tmp_path / "predictions.seal.json"
    gold = tmp_path / "gold.json"
    _prediction(prediction)
    gold.write_text(
        json.dumps(
            {
                "suite_id": "suite",
                "cases": [
                    {
                        "id": "one",
                        "obligations": [
                            {
                                "id": "format",
                                "path": "facts.format",
                                "equals": "PE",
                                "category": "exact_fact",
                            }
                        ],
                        "behaviors": ["file_io", "network_access"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    sealed = seal_predictions(prediction, seal)
    metrics, rows = score_predictions(prediction, seal, gold)

    assert sealed["prediction_sha256"]
    assert metrics["macro_obligation_score"] == 1.0
    assert metrics["behavior_precision"] == 1.0
    assert metrics["behavior_recall"] == 0.5
    assert metrics["behavior_f1"] == pytest.approx(2 / 3)
    assert metrics["exact_fact_accuracy"] == 1.0
    assert metrics["micro_obligation_score"] == 1.0
    assert metrics["evidence_coverage"] == 1.0
    assert rows[0]["obligations_passed"] == 1

    prediction.write_text(prediction.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256"):
        score_predictions(prediction, seal, gold)


def test_safety_violation_invalidates_score(tmp_path: Path) -> None:
    prediction = tmp_path / "predictions.json"
    seal = tmp_path / "predictions.seal.json"
    gold = tmp_path / "gold.json"
    _prediction(prediction)
    payload = json.loads(prediction.read_text(encoding="utf-8"))
    payload["safety"]["real_network_requests"] = 1
    prediction.write_text(json.dumps(payload), encoding="utf-8")
    gold.write_text(
        json.dumps({"suite_id": "suite", "cases": [{"id": "one", "obligations": [], "behaviors": []}]}),
        encoding="utf-8",
    )
    seal_predictions(prediction, seal)

    metrics, _ = score_predictions(prediction, seal, gold)

    assert metrics["safety_gate_passed"] is False
    assert metrics["macro_obligation_score"] == 0.0


def test_missing_or_unverified_safety_receipt_fails_closed(tmp_path: Path) -> None:
    prediction = tmp_path / "predictions.json"
    seal = tmp_path / "predictions.seal.json"
    gold = tmp_path / "gold.json"
    _prediction(prediction)
    payload = json.loads(prediction.read_text(encoding="utf-8"))
    del payload["safety"]["real_network_requests"]
    payload["safety_receipts"]["secret_leaks"]["status"] = "unknown"
    prediction.write_text(json.dumps(payload), encoding="utf-8")
    gold.write_text(
        json.dumps({"suite_id": "suite", "cases": [{"id": "one", "obligations": [], "behaviors": []}]}),
        encoding="utf-8",
    )
    seal_predictions(prediction, seal)

    metrics, _ = score_predictions(prediction, seal, gold)

    assert metrics["safety_gate_passed"] is False
    assert metrics["safety_receipts_complete"] is False


def test_score_rejects_duplicate_or_nonmatching_case_ids(tmp_path: Path) -> None:
    prediction = tmp_path / "predictions.json"
    seal = tmp_path / "predictions.seal.json"
    gold = tmp_path / "gold.json"
    _prediction(prediction)
    payload = json.loads(prediction.read_text(encoding="utf-8"))
    payload["cases"].append(dict(payload["cases"][0]))
    prediction.write_text(json.dumps(payload), encoding="utf-8")
    gold.write_text(
        json.dumps({"suite_id": "suite", "cases": [{"id": "one", "obligations": [], "behaviors": []}]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unique"):
        seal_predictions(prediction, seal)


def test_predict_stage_needs_only_public_manifest_not_gold(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "predictions.json"
    manifest.write_text(
        json.dumps({"schema_version": "1.0", "suite_id": "public-only", "cases": [], "safety": {}}),
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[1]

    result = predict_suite(
        manifest,
        output,
        arm="optimized",
        implementation_root=repo,
        suite_root=repo,
    )

    assert result["suite_id"] == "public-only"
    assert result["cases"] == []
    assert output.is_file()
