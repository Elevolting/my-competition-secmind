from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html
import json
import math
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from secmind.config import Settings
from secmind.live_source_review import BoundedSourceReviewAgent, SourceUnit
from secmind.llm import QwenGateway

MODEL_ID = "deepseek-v4-flash"
MODEL_BASE_URL = "https://api.deepseek.com"
PROMPT_VERSION = "secmind-v0.6-deepseek-source-review-v1"
CASE_IDS = (
    "BenchmarkTest00001",
    "BenchmarkTest00006",
    "BenchmarkTest00008",
    "BenchmarkTest00013",
    "BenchmarkTest00051",
    "BenchmarkTest00052",
    "BenchmarkTest00063",
    "BenchmarkTest00147",
)
SUPPORT_PATH = "helpers/SeparateClassRequest.java"
SINK_WINDOWS = {
    "BenchmarkTest00001": (71, 72),
    "BenchmarkTest00006": (62, 69),
    "BenchmarkTest00008": (52, 58),
    "BenchmarkTest00013": (54, 56),
    "BenchmarkTest00051": (58, 63),
    "BenchmarkTest00052": (48, 59),
    "BenchmarkTest00063": (71, 78),
    "BenchmarkTest00147": (60, 65),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _git_metadata() -> tuple[str | None, bool | None]:
    commit = os.environ.get("SECMIND_EVAL_GIT_COMMIT") or None
    dirty_raw = os.environ.get("SECMIND_EVAL_GIT_DIRTY")
    dirty = None if dirty_raw is None else dirty_raw.strip().lower() in {"1", "true", "yes"}
    return commit, dirty


def _load_sources(benchmark_root: Path) -> tuple[list[SourceUnit], list[SourceUnit]]:
    source_root = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark"
    cases: list[SourceUnit] = []
    for case_id in CASE_IDS:
        relative = f"testcode/{case_id}.java"
        content = (source_root / relative).read_text(encoding="utf-8")
        cases.append(SourceUnit(case_id=case_id, path=relative, content=content))
    helper = source_root / SUPPORT_PATH
    support = [
        SourceUnit(
            case_id="SeparateClassRequest",
            path=SUPPORT_PATH,
            content=helper.read_text(encoding="utf-8"),
        )
    ]
    return cases, support


def _selection_manifest(cases: list[SourceUnit], support: list[SourceUnit]) -> dict[str, Any]:
    units = [*cases, *support]
    manifest = {
        "schema_version": "1.0",
        "selection_locked_at": _now(),
        "selection_rule": "fixed balanced 8-case OWASP BenchmarkJava subset; four positive/negative category pairs",
        "gold_in_prompt": False,
        "excluded_inputs": ["expectedresults-1.2.csv", "scorecard/", "results/", "README and solution files"],
        "cases": [
            {"case_id": unit.case_id, "path": unit.path, "sha256": unit.sha256, "bytes": len(unit.content.encode())}
            for unit in cases
        ],
        "support_files": [
            {"case_id": unit.case_id, "path": unit.path, "sha256": unit.sha256, "bytes": len(unit.content.encode())}
            for unit in support
        ],
        "total_source_bytes": sum(len(unit.content.encode()) for unit in units),
    }
    manifest["selection_sha256"] = _sha256_bytes(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )
    return manifest


async def predict(benchmark_root: Path, report_dir: Path) -> None:
    api_key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required for the one bounded live request")
    raw_dir = report_dir / "raw"
    prediction_path = raw_dir / "model-predictions.json"
    if prediction_path.exists():
        raise SystemExit(f"sealed prediction already exists: {prediction_path}")

    cases, support = _load_sources(benchmark_root)
    selection = _selection_manifest(cases, support)
    _write_json(report_dir / "selection-manifest.json", selection)
    settings = Settings(
        env="evaluation",
        runtime_role="embedded",
        demo_mode=False,
        model_mode="live",
        allow_live_models=True,
        max_model_tier=5.4,
        trusted_model_base_urls=MODEL_BASE_URL,
        qwen_base_url=MODEL_BASE_URL,
        qwen_api_key=api_key,
        planner_model=MODEL_ID,
        worker_model=MODEL_ID,
        fallback_model=MODEL_ID,
        embedding_model="text-embedding-v3",
        model_reasoning_effort="high",
        model_thinking_enabled=True,
        model_max_output_tokens=32_768,
        model_max_attempts=1,
        max_model_calls=1,
        model_timeout_seconds=120,
    )
    gateway = QwenGateway(settings)
    agent = BoundedSourceReviewAgent(gateway)
    run_id = f"live-gold-{uuid4()}"
    started_at = _now()
    try:
        output, meta = await agent.review(cases, support_files=support, run_id=run_id)
    finally:
        await gateway.close()
    sealed_at = _now()
    prediction_payload = {
        "schema_version": "1.0",
        "experiment_kind": "experimental-v0.6-bounded-source-review-specialist",
        "run_id": run_id,
        "started_at": started_at,
        "prediction_sealed_at": sealed_at,
        "model_id": meta.model_id,
        "prompt_version": meta.prompt_version,
        "response_sha256": meta.response_sha256,
        "duration_ms": meta.duration_ms,
        "used_fallback": meta.used_fallback,
        "selection_sha256": selection["selection_sha256"],
        "predictions": [item.model_dump(mode="json") for item in output.predictions],
        "limitations": output.limitations,
    }
    _write_json(prediction_path, prediction_payload)
    attempts = gateway.provider_attempts_for(run_id)
    input_tokens = sum(item.usage.input_tokens for item in attempts)
    output_tokens = sum(item.usage.output_tokens for item in attempts)
    estimated_upper_usd = input_tokens * 0.14 / 1_000_000 + output_tokens * 0.28 / 1_000_000
    _write_json(
        raw_dir / "model-usage.json",
        {
            "schema_version": "1.0",
            "provider_requests": len(attempts),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "latency_ms": meta.duration_ms,
            "pricing_snapshot": {
                "observed_at": "2026-07-15",
                "currency": "USD",
                "cache_hit_input_per_million": 0.0028,
                "cache_miss_input_per_million": 0.14,
                "output_per_million": 0.28,
                "source": "https://api-docs.deepseek.com/quick_start/pricing",
            },
            "estimated_cost_upper_bound_usd": round(estimated_upper_usd, 8),
            "cost_note": "Conservative cache-miss estimate; not a provider invoice.",
            "attempts": [
                {
                    "attempt_id": item.provider_request_id,
                    "sequence": item.sequence,
                    "model_id": item.model_id,
                    "status_code": item.status_code,
                    "succeeded": item.succeeded,
                    "retryable": item.retryable,
                    "error_type": item.error_type,
                    "input_tokens": item.usage.input_tokens,
                    "output_tokens": item.usage.output_tokens,
                    "latency_ms": item.duration_ms,
                }
                for item in attempts
            ],
        },
    )
    print(json.dumps({"prediction_path": str(prediction_path), "provider_requests": len(attempts)}))


def _load_gold(benchmark_root: Path) -> tuple[dict[str, dict[str, Any]], str]:
    gold_path = benchmark_root / "expectedresults-1.2.csv"
    gold: dict[str, dict[str, Any]] = {}
    with gold_path.open(encoding="utf-8", newline="") as stream:
        rows = csv.reader(line for line in stream if not line.startswith("#"))
        for row in rows:
            if len(row) != 4 or row[0] not in CASE_IDS:
                continue
            gold[row[0]] = {
                "case_id": row[0],
                "category": row[1],
                "gold_vulnerable": row[2].strip().lower() == "true",
                "cwe": int(row[3]),
                "sink_window": list(SINK_WINDOWS[row[0]]),
            }
    if set(gold) != set(CASE_IDS):
        raise ValueError("gold CSV does not contain the complete locked selection")
    return gold, _sha256_file(gold_path)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _score(
    prediction_payload: dict[str, Any], gold: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    predictions = {item["case_id"]: item for item in prediction_payload["predictions"]}
    if set(predictions) != set(CASE_IDS):
        raise ValueError("sealed predictions do not match the locked case ids")
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    evidence_bound = location_hits = positive_predictions = true_positive_predictions = 0
    off_taxonomy = 0
    for case_id in CASE_IDS:
        expected = gold[case_id]
        predicted = predictions[case_id]
        cwe_match = predicted.get("cwe") == expected["cwe"]
        predicted_positive = bool(predicted["vulnerable"] and cwe_match)
        if predicted.get("vulnerable") and not cwe_match:
            off_taxonomy += 1
        if expected["gold_vulnerable"] and predicted_positive:
            verdict = "TP"
            tp += 1
            true_positive_predictions += 1
        elif expected["gold_vulnerable"]:
            verdict = "FN"
            fn += 1
        elif predicted_positive:
            verdict = "FP"
            fp += 1
        else:
            verdict = "TN"
            tn += 1
        if predicted["vulnerable"]:
            positive_predictions += 1
        bound = bool(predicted.get("evidence_path") and predicted.get("evidence_sha256"))
        evidence_bound += int(bound)
        sink_line = predicted.get("sink_line")
        window = expected["sink_window"]
        location_valid = bool(verdict == "TP" and isinstance(sink_line, int) and window[0] <= sink_line <= window[1])
        location_hits += int(location_valid)
        rows.append(
            {
                "case_id": case_id,
                "category": expected["category"],
                "gold_cwe": expected["cwe"],
                "gold_vulnerable": expected["gold_vulnerable"],
                "predicted_vulnerable_raw": predicted["vulnerable"],
                "predicted_cwe": predicted.get("cwe"),
                "scored_positive": predicted_positive,
                "verdict": verdict,
                "confidence": predicted["confidence"],
                "sink_line": sink_line,
                "sink_window": f"{window[0]}-{window[1]}",
                "location_valid": location_valid,
                "evidence_bound": bound,
                "rationale_summary": predicted["rationale_summary"],
            }
        )
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    accuracy = _ratio(tp + tn, len(CASE_IDS))
    f1 = _ratio(2 * tp, 2 * tp + fp + fn)
    fpr = _ratio(fp, fp + tn)
    metrics = {
        "sample_count": len(CASE_IDS),
        "positive_gold": tp + fn,
        "negative_gold": tn + fp,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "f1": f1,
        "balanced_accuracy": (
            round((recall + specificity) / 2, 6) if recall is not None and specificity is not None else None
        ),
        "owasp_mini_score": round(100 * (recall - fpr), 2) if recall is not None and fpr is not None else None,
        "accuracy_wilson_95": _wilson(tp + tn, len(CASE_IDS)),
        "recall_wilson_95": _wilson(tp, tp + fn),
        "finding_to_evidence_binding": _ratio(evidence_bound, len(CASE_IDS)),
        "true_positive_sink_location_rate": _ratio(location_hits, true_positive_predictions),
        "raw_positive_predictions": positive_predictions,
        "off_taxonomy_positive_predictions": off_taxonomy,
    }
    return rows, metrics


def _render_markdown(metrics: dict[str, Any], rows: list[dict[str, Any]], usage: dict[str, Any]) -> str:
    cm = metrics["confusion_matrix"]
    lines = [
        "# SecMind v0.6 DeepSeek V4 Flash 定向金标实验报告",
        "",
        "## 技术摘要",
        "",
        f"本次实验在 8 个固定 OWASP BenchmarkJava 用例上进行一次、金标隔离的静态源码审计。"
        f"结果为 TP={cm['tp']}、FP={cm['fp']}、TN={cm['tn']}、FN={cm['fn']}；"
        f"Precision={metrics['precision']}，Recall={metrics['recall']}，F1={metrics['f1']}，"
        f"Accuracy={metrics['accuracy']}。模型请求共 {usage['provider_requests']} 次（成功 "
        f"{usage['successful_provider_requests']}、截断失败 {usage['failed_provider_requests']}）；成功请求由 Provider "
        f"计量 {usage['total_tokens']} Token，按全部输入未命中缓存估算两次请求费用上限 "
        f"${usage['estimated_cost_upper_bound_usd']:.8f}。失败请求 Token 未被本地持久化，因此不并入 Token 总数。",
        "",
        "## 逐题结果证明了什么",
        "",
        "| Case | Gold | Pred | CWE | Verdict | Line | Evidence |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['case_id']} | {str(row['gold_vulnerable']).lower()} | "
            f"{str(row['predicted_vulnerable_raw']).lower()} | {row['predicted_cwe'] or '-'} | "
            f"{row['verdict']} | {row['sink_line'] or '-'} | {str(row['evidence_bound']).lower()} |"
        )
    lines += [
        "",
        "## 范围、指标与方法",
        "",
        "样本覆盖 CWE-22、78、79、89，每类各一条阳性和一条阴性。模型只接收 8 个测试源码和一个必要的帮助类，"
        "不接收 expectedresults CSV、scorecard、历史报告或答案。预测先落盘并封存哈希，"
        "随后由不调用模型的评分阶段读取金标。"
        "每题只产生一个分类位；只有 vulnerable=true 且 CWE 与该题目标类别一致才计为阳性。",
        "",
        "## 限制与稳健性",
        "",
        f"Accuracy 的 Wilson 95% 区间为 {metrics['accuracy_wilson_95']}，Recall 区间为 "
        f"{metrics['recall_wilson_95']}。样本仅 8 题且来自公开 BenchmarkJava，可能存在训练数据记忆；"
        "它不能代表完整 2,740 题 BenchmarkJava、全语言能力、主 LangGraph 端到端能力、沙箱安全或故障恢复能力。"
        "当前 v0.6 主图仍以确定性编排为主，本次评估对象是新增的受限源码审计专家。",
        "",
        "## 建议的下一步",
        "",
        "- 扩展为盲选 40 题并保持一次批请求或严格的小批预算。",
        "- 把该专家作为 Java 工具缺失时的受控补充节点，而不是替代 Broker、Verifier 或金标工具链。",
        "- 修复模型费用的数据库持久化，记录缓存命中和 reasoning token 后再做正式成本比较。",
        "",
        "## 仍待回答的问题",
        "",
        "公开样本上的表现能否迁移到未见过的多文件 Java 项目，以及在 Semgrep/OSV 等确定性工具加入后，"
        "模型的边际收益是否仍高于成本。",
        "",
    ]
    return "\n".join(lines)


def _render_html(markdown_text: str, metrics: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    cm = metrics["confusion_matrix"]
    table_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in (
                row["case_id"],
                row["gold_vulnerable"],
                row["predicted_vulnerable_raw"],
                row["predicted_cwe"] or "-",
                row["verdict"],
                row["sink_line"] or "-",
                row["location_valid"],
            )
        )
        + "</tr>"
        for row in rows
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>SecMind v0.6 定向金标实验</title>
  <style>
    body {{ font: 16px/1.65 system-ui; max-width: 1060px; margin: auto; padding: 32px }}
    h1, h2 {{ line-height: 1.25 }}
    .kpis {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 12px }}
    .kpi {{ border: 1px solid #8885; border-radius: 10px; padding: 14px }}
    .v {{ font-size: 1.7rem; font-weight: 700 }}
    table {{ border-collapse: collapse; width: 100%; overflow: auto; display: block }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid #8885; text-align: left }}
    code {{ background: #8882; padding: 2px 5px; border-radius: 4px }}
    .caveat {{ border-left: 4px solid #d89b00; padding: 10px 14px; background: #d89b0014 }}
  </style>
</head>
<body>
  <h1>SecMind v0.6 DeepSeek V4 Flash 定向金标实验</h1>
  <h2>技术摘要</h2>
  <p>一次请求完成 8 个固定 OWASP BenchmarkJava 用例的金标隔离源码审计。
  混淆矩阵为 TP={cm["tp"]}、FP={cm["fp"]}、TN={cm["tn"]}、FN={cm["fn"]}。</p>
  <div class="kpis">
    <div class="kpi"><div>Precision</div><div class="v">{metrics["precision"]}</div></div>
    <div class="kpi"><div>Recall</div><div class="v">{metrics["recall"]}</div></div>
    <div class="kpi"><div>F1</div><div class="v">{metrics["f1"]}</div></div>
    <div class="kpi"><div>Accuracy</div><div class="v">{metrics["accuracy"]}</div></div>
  </div>
  <h2>逐题结果</h2>
  <p>每题只计一个预测位；只有 CWE 与金标类别一致的阳性预测进入混淆矩阵。</p>
  <table><thead><tr><th>Case</th><th>Gold</th><th>Pred</th><th>CWE</th>
  <th>Verdict</th><th>Line</th><th>Location</th></tr></thead><tbody>{table_rows}</tbody></table>
  <h2>范围、数据与方法</h2>
  <p>样本覆盖 CWE-22、78、79、89，每类各一条阳性和一条阴性。模型只接收锁定源码；
  预测封存后，评分器才读取 <code>expectedresults-1.2.csv</code>。</p>
  <h2>限制与稳健性</h2>
  <div class="caveat">这是公开基准的 8 题定向小样本，不是完整 BenchmarkJava，也不是 v0.6 主
  LangGraph、Runner、恢复与并发能力的端到端发布验收。Accuracy Wilson 95% 区间为
  {metrics["accuracy_wilson_95"]}，Recall 区间为 {metrics["recall_wilson_95"]}。</div>
  <h2>建议的下一步</h2>
  <ol><li>盲选扩展到 40 题，同时继续限制模型请求和输出预算。</li>
  <li>将专家作为 Java 工具缺失时的受控补充节点。</li>
  <li>加入模型费用、缓存和 reasoning token 的持久化。</li></ol>
  <h2>审计材料</h2>
  <p>同目录保存选择清单、原始预测、逐题 CSV、指标 JSON、金标快照和 SHA-256 清单。
  Markdown 正文与本页内容来自同一评分结果。</p>
</body>
</html>
"""


def score(benchmark_root: Path, report_dir: Path) -> None:
    prediction_path = report_dir / "raw" / "model-predictions.json"
    usage_path = report_dir / "raw" / "model-usage.json"
    selection_path = report_dir / "selection-manifest.json"
    predictions = json.loads(prediction_path.read_text(encoding="utf-8"))
    usage = json.loads(usage_path.read_text(encoding="utf-8"))
    failed_path = report_dir / "raw" / "failed-attempts.json"
    failed_attempts = json.loads(failed_path.read_text(encoding="utf-8"))["attempts"] if failed_path.exists() else []
    combined_usage = dict(usage)
    combined_usage["successful_provider_requests"] = usage["provider_requests"]
    combined_usage["failed_provider_requests"] = len(failed_attempts)
    combined_usage["provider_requests"] = usage["provider_requests"] + len(failed_attempts)
    combined_usage["estimated_cost_upper_bound_usd"] = round(
        usage["estimated_cost_upper_bound_usd"]
        + sum(float(item["estimated_cost_upper_bound_usd"]) for item in failed_attempts),
        8,
    )
    combined_usage["usage_accounting_note"] = (
        "Successful request tokens are provider-reported. The earlier truncated request did not survive process exit; "
        "its tokens and cost are conservatively estimated and are not included in total_tokens."
    )
    _write_json(report_dir / "raw" / "experiment-usage-summary.json", combined_usage)
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    gold_loaded_at = _now()
    gold, gold_csv_sha256 = _load_gold(benchmark_root)
    rows, metrics = _score(predictions, gold)
    metrics.update(
        {
            "schema_version": "1.0",
            "prediction_sha256": _sha256_file(prediction_path),
            "gold_csv_sha256": gold_csv_sha256,
            "gold_loaded_at": gold_loaded_at,
            "prediction_sealed_at": predictions["prediction_sealed_at"],
            "gold_loaded_after_prediction": gold_loaded_at >= predictions["prediction_sealed_at"],
        }
    )
    _write_json(report_dir / "gold" / "gold-labels.json", {"source_sha256": gold_csv_sha256, "cases": gold})
    _write_json(report_dir / "scoring" / "metrics.json", metrics)
    verdict_path = report_dir / "scoring" / "case-verdicts.csv"
    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    with verdict_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    commit, dirty = _git_metadata()
    manifest = {
        "report_schema": "1.0",
        "product_version": "0.6.0rc1",
        "public_schema": "1.3",
        "experiment_kind": predictions["experiment_kind"],
        "run_id": predictions["run_id"],
        "started_at": predictions["started_at"],
        "ended_at": _now(),
        "timezone": "UTC",
        "host": platform.platform(),
        "python": sys.version.split()[0],
        "git_commit": commit,
        "dirty_tree": dirty,
        "dataset": {
            "name": "OWASP BenchmarkJava 1.2 targeted balanced mini-set",
            "case_count": len(CASE_IDS),
            "gold_sha256": gold_csv_sha256,
            "selection_sha256": selection["selection_sha256"],
        },
        "model": {
            "provider": "DeepSeek",
            "model_id": MODEL_ID,
            "model_tier": 4.0,
            "base_url_host": "api.deepseek.com",
            "reasoning_effort": "high",
            "max_output_tokens": 32_768,
            "temperature": None,
        },
        "budget": {"max_provider_requests": 1, "max_output_tokens": 32_768, "max_wall_seconds": 120},
        "usage": {
            key: combined_usage[key]
            for key in (
                "provider_requests",
                "successful_provider_requests",
                "failed_provider_requests",
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "latency_ms",
                "estimated_cost_upper_bound_usd",
            )
        },
        "gold_access_policy": (
            "Predict process excludes labels from input; score process loads gold only after sealed prediction and "
            "makes no model call. This is process-flow separation, not cryptographic isolation."
        ),
        "limitations": [
            "Public eight-case targeted sample; possible benchmark memorization.",
            "Experimental bounded source-review specialist, not the complete v0.6 orchestration graph.",
            "Cost is an upper-bound estimate, not a provider invoice.",
        ],
    }
    _write_json(report_dir / "experiment-manifest.json", manifest)
    markdown = _render_markdown(metrics, rows, combined_usage)
    (report_dir / "README.md").write_text(markdown, encoding="utf-8")
    (report_dir / "report.html").write_text(_render_html(markdown, metrics, rows), encoding="utf-8")
    hash_targets = sorted(path for path in report_dir.rglob("*") if path.is_file() and path.name != "hashes.sha256")
    (report_dir / "hashes.sha256").write_text(
        "".join(f"{_sha256_file(path)}  {path.relative_to(report_dir).as_posix()}\n" for path in hash_targets),
        encoding="utf-8",
    )
    print(json.dumps({"report": str(report_dir / "README.md"), "metrics": metrics}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run or score the one-request SecMind live Java source review")
    parser.add_argument("phase", choices=("predict", "score"))
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.phase == "predict":
        asyncio.run(predict(arguments.benchmark_root.resolve(), arguments.report_dir.resolve()))
    else:
        score(arguments.benchmark_root.resolve(), arguments.report_dir.resolve())


if __name__ == "__main__":
    main()
