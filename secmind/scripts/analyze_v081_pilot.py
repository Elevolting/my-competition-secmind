from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from statistics import mean
from typing import Any

from score_comprehensive_offline import DATASET_VERSION, aggregate, score_one

SCRIPT_DIR = Path(__file__).resolve().parent


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_analysis_code() -> dict[str, str]:
    return {
        "evaluator_sha256": file_sha256(SCRIPT_DIR / "evaluate_comprehensive_public.py"),
        "scorer_sha256": file_sha256(SCRIPT_DIR / "score_comprehensive_offline.py"),
        "analyzer_sha256": file_sha256(Path(__file__).resolve()),
    }


def load_private(private_root: Path) -> dict[str, dict[str, Any]]:
    manifest = json.loads((private_root / "answer-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("dataset_version") != DATASET_VERSION:
        raise SystemExit("private scorer dataset identity mismatch")
    private_by_id: dict[str, dict[str, Any]] = {}
    for item in manifest["answers"]:
        path = private_root / item["path"]
        if file_sha256(path) != item["sha256"]:
            raise SystemExit(f"private answer hash mismatch: {item['task_id']}")
        private_by_id[item["task_id"]] = json.loads(path.read_text(encoding="utf-8"))
    return private_by_id


def load_and_verify_seal(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sealed = json.loads(path.read_text(encoding="utf-8"))
    if sealed.get("dataset_version") != DATASET_VERSION:
        raise SystemExit(f"sealed dataset identity mismatch: {path}")
    rounds = sealed.get("rounds") or []
    if not rounds:
        raise SystemExit(f"sealed output has no rounds: {path}")
    commitment_rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for round_data in rounds:
        current = round_data.get("records") or []
        submission = {"dataset_version": DATASET_VERSION, "results": [row["result"] for row in current]}
        submission_sha256 = canonical_sha256(submission)
        if submission_sha256 != round_data.get("submission_sha256"):
            raise SystemExit(f"round submission commitment mismatch: {path}")
        commitment_rows.append({"repetition": int(round_data["repetition"]), "submission_sha256": submission_sha256})
        for row in current:
            records.append({"repetition": int(round_data["repetition"]), **row})
    if canonical_sha256(commitment_rows) != sealed.get("prediction_commitment_sha256"):
        raise SystemExit(f"prediction commitment mismatch: {path}")
    if len(records) != int(sealed.get("case_count", 0)) * len(rounds):
        raise SystemExit(f"incomplete sealed records: {path}")
    return sealed, records


def score_records(
    records: Iterable[dict[str, Any]],
    private_by_id: dict[str, dict[str, Any]],
    public_root: Path,
    *,
    result_field: str = "result",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        task_id = record["task_id"]
        result = record.get(result_field)
        if not isinstance(result, dict):
            raise SystemExit(f"missing {result_field}: {task_id}")
        projected = {**record, "result": result}
        rows.append(
            {
                "repetition": int(record["repetition"]),
                **score_one(projected, private_by_id[task_id], public_root),
            }
        )
    return rows


def delta_summary(final_rows: list[dict[str, Any]], primary_rows: list[dict[str, Any]]) -> dict[str, Any]:
    primary_by_key = {(row["repetition"], row["task_id"]): row for row in primary_rows}
    deltas: list[dict[str, Any]] = []
    for final in final_rows:
        primary = primary_by_key[(final["repetition"], final["task_id"])]
        delta = round(final["score"] - primary["score"], 6)
        deltas.append(
            {
                "task_id": final["task_id"],
                "repetition": final["repetition"],
                "domain": final["domain"],
                "primary_score": primary["score"],
                "final_score": final["score"],
                "delta": delta,
                "primary_finding_count": primary["finding_count"],
                "final_finding_count": final["finding_count"],
            }
        )
    return {
        "mean_delta": round(mean(item["delta"] for item in deltas), 6),
        "improved": sum(item["delta"] > 0 for item in deltas),
        "unchanged": sum(item["delta"] == 0 for item in deltas),
        "regressed": sum(item["delta"] < 0 for item in deltas),
        "regressions": [item for item in deltas if item["delta"] < 0],
        "improvements": [item for item in deltas if item["delta"] > 0],
    }


def usage_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    attempts = [attempt for record in records for attempt in record.get("provider_attempts", [])]
    return {
        "provider_requests": len(attempts),
        "input_tokens": sum(int(item.get("input_tokens", 0)) for item in attempts),
        "output_tokens": sum(int(item.get("output_tokens", 0)) for item in attempts),
        "total_tokens": sum(int(item.get("input_tokens", 0)) + int(item.get("output_tokens", 0)) for item in attempts),
        "summed_task_duration_ms": sum(int(item.get("duration_ms", 0)) for item in records),
        "model_calls_used": sum(int(item.get("model_calls_used", 0)) for item in records),
        "tool_calls_used": sum(int(item.get("tool_calls_used", 0)) for item in records),
    }


def analyze_suite(
    suite_root: Path,
    private_by_id: dict[str, dict[str, Any]],
    public_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    direct_seal, direct_records = load_and_verify_seal(suite_root / "direct" / "sealed-predictions.json")
    agent_seal, agent_records = load_and_verify_seal(suite_root / "v071" / "sealed-predictions.json")
    direct_ids = {(row["repetition"], row["task_id"]) for row in direct_records}
    agent_ids = {(row["repetition"], row["task_id"]) for row in agent_records}
    if direct_ids != agent_ids:
        raise SystemExit(f"arm case identity mismatch: {suite_root.name}")
    for label, sealed in (("direct", direct_seal), ("v071", agent_seal)):
        controls = sealed.get("controls") or {}
        if controls.get("source_commit") != "86bea9f" or str(controls.get("source_dirty")).lower() != "false":
            raise SystemExit(f"{label} is not bound to clean v0.7.1: {suite_root.name}")

    direct_rows = score_records(direct_records, private_by_id, public_root)
    final_rows = score_records(agent_records, private_by_id, public_root)
    primary_rows = score_records(
        agent_records,
        private_by_id,
        public_root,
        result_field="canonical_counterfactual_result",
    )
    direct_metrics = aggregate(direct_rows)
    final_metrics = aggregate(final_rows)
    primary_metrics = aggregate(primary_rows)
    comparison = {
        "independent_arm_score_delta": round(final_metrics["overall_score"] - direct_metrics["overall_score"], 6),
        "independent_arm_causal_warning": (
            "Direct and v0.7.1 used separate stochastic provider samples; this delta is descriptive, not causal."
        ),
        "same_receipt_downstream": delta_summary(final_rows, primary_rows),
    }
    records_by_key = {(row["repetition"], row["task_id"]): row for row in agent_records}
    task_rows: list[dict[str, Any]] = []
    direct_by_key = {(row["repetition"], row["task_id"]): row for row in direct_rows}
    primary_by_key = {(row["repetition"], row["task_id"]): row for row in primary_rows}
    for final in final_rows:
        key = (final["repetition"], final["task_id"])
        direct = direct_by_key[key]
        primary = primary_by_key[key]
        agent_record = records_by_key[key]
        task_rows.append(
            {
                "suite": suite_root.name,
                "task_id": final["task_id"],
                "repetition": final["repetition"],
                "domain": final["domain"],
                "project": final["project"],
                "language": final["language"],
                "direct_score": direct["score"],
                "v071_primary_score": primary["score"],
                "v071_final_score": final["score"],
                "downstream_delta": round(final["score"] - primary["score"], 6),
                "direct_findings": direct["finding_count"],
                "primary_findings": primary["finding_count"],
                "final_findings": final["finding_count"],
                "provider_requests": len(agent_record.get("provider_attempts", [])),
                "tool_calls": int(agent_record.get("tool_calls_used", 0)),
                "agent_duration_ms": int(agent_record.get("duration_ms", 0)),
            }
        )
    return (
        {
            "case_observations": len(final_rows),
            "direct": {"metrics": direct_metrics, "usage": usage_summary(direct_records)},
            "v071_primary_same_receipt": {"metrics": primary_metrics},
            "v071_final": {"metrics": final_metrics, "usage": usage_summary(agent_records)},
            "comparison": comparison,
            "seals": {
                "direct": direct_seal["prediction_commitment_sha256"],
                "v071": agent_seal["prediction_commitment_sha256"],
            },
        },
        task_rows,
    )


def analyze_agent_only_suite(
    suite_root: Path,
    private_by_id: dict[str, dict[str, Any]],
    public_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    agent_seal, agent_records = load_and_verify_seal(suite_root / "v071" / "sealed-predictions.json")
    controls = agent_seal.get("controls") or {}
    if controls.get("source_commit") != "86bea9f" or str(controls.get("source_dirty")).lower() != "false":
        raise SystemExit(f"v071 is not bound to clean v0.7.1: {suite_root.name}")
    final_rows = score_records(agent_records, private_by_id, public_root)
    primary_rows = score_records(
        agent_records,
        private_by_id,
        public_root,
        result_field="canonical_counterfactual_result",
    )
    comparison = delta_summary(final_rows, primary_rows)
    primary_by_key = {(row["repetition"], row["task_id"]): row for row in primary_rows}
    records_by_key = {(row["repetition"], row["task_id"]): row for row in agent_records}
    task_rows: list[dict[str, Any]] = []
    for final in final_rows:
        key = (final["repetition"], final["task_id"])
        primary = primary_by_key[key]
        agent_record = records_by_key[key]
        task_rows.append(
            {
                "suite": suite_root.name,
                "task_id": final["task_id"],
                "repetition": final["repetition"],
                "domain": final["domain"],
                "project": final["project"],
                "language": final["language"],
                "direct_score": "",
                "v071_primary_score": primary["score"],
                "v071_final_score": final["score"],
                "downstream_delta": round(final["score"] - primary["score"], 6),
                "direct_findings": "",
                "primary_findings": primary["finding_count"],
                "final_findings": final["finding_count"],
                "provider_requests": len(agent_record.get("provider_attempts", [])),
                "tool_calls": int(agent_record.get("tool_calls_used", 0)),
                "agent_duration_ms": int(agent_record.get("duration_ms", 0)),
            }
        )
    return (
        {
            "case_observations": len(final_rows),
            "unique_tasks": len({row["task_id"] for row in final_rows}),
            "comparison_type": "same_receipt_downstream_only",
            "v071_primary_same_receipt": {"metrics": aggregate(primary_rows)},
            "v071_final": {"metrics": aggregate(final_rows), "usage": usage_summary(agent_records)},
            "comparison": {"same_receipt_downstream": comparison},
            "seals": {"v071": agent_seal["prediction_commitment_sha256"]},
        },
        task_rows,
    )


def write_outputs(output_dir: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_code = current_analysis_code()
    summary = {**summary, "current_analysis_code": analysis_code}
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = list(rows[0]) if rows else []
    with (output_dir / "task-scores.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    reproducibility_path = output_dir / "reproducibility.json"
    if reproducibility_path.exists():
        reproducibility = json.loads(reproducibility_path.read_text(encoding="utf-8"))
        reproducibility["current_analysis_code"] = analysis_code
        reproducibility_path.write_text(
            json.dumps(reproducibility, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify and analyze the clean-v0.7.1 DeepSeek v0.8 pilot")
    parser.add_argument("--pilot-root", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    private_by_id = load_private(args.private_root.resolve())
    suites: dict[str, Any] = {}
    all_rows: list[dict[str, Any]] = []
    for suite_root in sorted(path for path in args.pilot_root.resolve().iterdir() if path.is_dir()):
        has_direct = (suite_root / "direct" / "sealed-predictions.json").exists()
        has_agent = (suite_root / "v071" / "sealed-predictions.json").exists()
        if not has_agent:
            continue
        if has_direct:
            suites[suite_root.name], rows = analyze_suite(suite_root, private_by_id, args.public_root.resolve())
        else:
            suites[suite_root.name], rows = analyze_agent_only_suite(
                suite_root, private_by_id, args.public_root.resolve()
            )
        all_rows.extend(rows)
    if not suites:
        raise SystemExit("no complete pilot suites found")
    summary = {
        "schema_version": "1.0",
        "dataset_version": DATASET_VERSION,
        "offline_analysis": True,
        "provider_requests_by_analyzer": 0,
        "causal_boundary": (
            "Only v0.7.1 canonical-counterfactual versus final is a same-receipt downstream comparison. "
            "Direct versus v0.7.1 used independent model samples."
        ),
        "suites": suites,
    }
    write_outputs(args.output_dir.resolve(), summary, all_rows)
    print(json.dumps({"suites": list(suites), "rows": len(all_rows)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
