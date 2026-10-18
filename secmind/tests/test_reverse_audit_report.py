from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secmind.reverse_evaluation import seal_predictions
from secmind.reverse_report import _copy_live_artifacts, _load_live_pair, render_audit_report


def test_audit_report_is_self_contained_and_uses_metrics_truth(tmp_path: Path) -> None:
    results = tmp_path / "results"
    gold = tmp_path / "gold.json"
    gold.write_text(
        json.dumps({"schema_version": "1.1", "suite_id": "suite", "cases": [{"id": "case"}]}),
        encoding="utf-8",
    )
    for index, arm in enumerate(("old", "current", "optimized")):
        directory = results / arm
        directory.mkdir(parents=True)
        metrics = {
            "macro_obligation_score": 0.5 + index * 0.2,
            "behavior_f1": 0.4 + index * 0.1,
            "exact_fact_accuracy": 0.6,
            "evidence_coverage": 0.7,
            "completion_rate": 0.8,
            "partial_rate": 0.2,
            "timeout_rate": 0.0,
            "safety_gate_passed": True,
            "safety": {"real_network_requests": 0, "host_pe_executions": 0, "target_writes": 0, "secret_leaks": 0},
        }
        (directory / "predictions.json").write_text(
            json.dumps(
                {
                    "suite_id": "suite",
                    "cases": [
                        {"id": "case", "status": "completed", "facts": {}, "behaviors": [], "evidence_refs": []}
                    ],
                }
            ),
            encoding="utf-8",
        )
        sealed = seal_predictions(directory / "predictions.json", directory / "predictions.seal.json")
        metrics["prediction_sha256"] = sealed["prediction_sha256"]
        metrics["gold_sha256"] = hashlib.sha256(gold.read_bytes()).hexdigest()
        (directory / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")

    output = tmp_path / "report"
    (output / "raw-reports").mkdir(parents=True)
    (output / "raw-reports" / "sample.json").write_text('{"safe": true}\n', encoding="utf-8")
    (output / "live-preflight.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "ready": False,
                "reason": "missing_deepseek_credential",
                "gold_read": False,
                "network_requests_made": 0,
                "case_count": 12,
                "arms": {
                    "current": {"seal_verified": True},
                    "optimized": {"seal_verified": True},
                },
            }
        ),
        encoding="utf-8",
    )
    artifacts = render_audit_report(
        results,
        output,
        live_status="blocked_missing_credential",
        gold_path=gold,
    )
    html = artifacts["html"].read_text(encoding="utf-8")
    aggregate = json.loads(artifacts["metrics"].read_text(encoding="utf-8"))

    assert "0.900" in html
    assert "blocked_missing_credential" in html
    assert "Live 预检" in html
    assert "12 题封印已验证" in html
    assert 'src="http' not in html and 'href="http' not in html
    assert aggregate["offline"]["optimized"]["macro_obligation_score"] == 0.9
    assert artifacts["csv"].read_text(encoding="utf-8").count("\n") == 4
    manifest = json.loads(artifacts["manifest"].read_text(encoding="utf-8"))
    sample_artifact = next(item for item in manifest["report_artifacts"] if item["path"] == "raw-reports/sample.json")
    assert len(sample_artifact["sha256"]) == 64
    assert manifest["planned_live_model"]["cost_status"] == "not_run"
    assert manifest["planned_live_model"]["preflight"]["reason"] == "missing_deepseek_credential"
    assert len(manifest["planned_live_model"]["preflight_sha256"]) == 64
    assert manifest["safety"]["network_scope"] == "sample_and_reverse_tools_only"
    assert manifest["gold"]["sha256"]


def test_report_rejects_completed_live_status_without_sealed_pair(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing current artifacts"):
        _load_live_pair(tmp_path, "completed_exploratory_pair")


def test_report_loads_only_sealed_live_pair_with_metrics_tokens_and_cost(tmp_path: Path) -> None:
    for arm in ("current", "optimized"):
        prediction = tmp_path / f"live-{arm}.json"
        prediction.write_text(
            json.dumps(
                {
                    "suite_id": "suite",
                    "arm": arm,
                    "cases": [
                        {
                            "id": "case",
                            "status": "completed",
                            "model_receipt": {"model_receipt_id": f"receipt-{arm}"},
                        }
                    ],
                    "aggregate_receipt": {"total_tokens": 123},
                    "pricing": {"estimated_cny": 0.01},
                }
            ),
            encoding="utf-8",
        )
        sealed = seal_predictions(prediction, tmp_path / f"live-{arm}.seal.json")
        (tmp_path / f"live-{arm}.metrics.json").write_text(
            json.dumps(
                {
                    "prediction_sha256": sealed["prediction_sha256"],
                    "macro_obligation_score": 0.8,
                    "completion_rate": 1.0,
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / f"live-{arm}-case-results.csv").write_text("case_id\ncase\n", encoding="utf-8")

    payload = _load_live_pair(tmp_path, "completed_exploratory_pair")

    assert payload["arms"]["current"]["aggregate_receipt"]["total_tokens"] == 123
    assert payload["arms"]["optimized"]["pricing"]["estimated_cny"] == 0.01
    assert payload["arms"]["current"]["model_receipt_count"] == 1
    assert payload["arms"]["current"]["model_failure_count"] == 0


def test_report_copies_live_raw_and_normalized_artifacts(tmp_path: Path) -> None:
    live_root = tmp_path / "live"
    output = tmp_path / "report"
    live_root.mkdir()
    for arm in ("current", "optimized"):
        for suffix in (".json", ".seal.json", ".metrics.json", "-case-results.csv"):
            (live_root / f"live-{arm}{suffix}").write_text(f"{arm}:{suffix}\n", encoding="utf-8")

    _copy_live_artifacts(live_root, output)

    for arm in ("current", "optimized"):
        assert (output / "raw-reports" / f"live-{arm}.json").is_file()
        assert (output / "raw-reports" / f"live-{arm}.seal.json").is_file()
        assert (output / "normalized-reports" / f"live-{arm}.metrics.json").is_file()
        assert (output / "normalized-reports" / f"live-{arm}-case-results.csv").is_file()
