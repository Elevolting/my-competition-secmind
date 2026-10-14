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

import secmind.live_source_review as source_review
from secmind.config import Settings
from secmind.live_source_review import SourceUnit
from secmind.llm import ModelGatewayError, QwenGateway

BoundedSourceReviewAgent = getattr(source_review, "BoundedSourceReviewAgent", None)

MODEL_ID = "deepseek-v4-flash"
MODEL_BASE_URL = "https://api.deepseek.com"
REPETITIONS = 3
BATCHES: tuple[tuple[str, ...], ...] = (
    (
        "BenchmarkTest00001",
        "BenchmarkTest00218",
        "BenchmarkTest00359",
        "BenchmarkTest00619",
        "BenchmarkTest00783",
        "BenchmarkTest00063",
        "BenchmarkTest00134",
        "BenchmarkTest00217",
        "BenchmarkTest00784",
        "BenchmarkTest00862",
    ),
    (
        "BenchmarkTest00006",
        "BenchmarkTest00077",
        "BenchmarkTest00294",
        "BenchmarkTest00495",
        "BenchmarkTest00815",
        "BenchmarkTest00051",
        "BenchmarkTest00305",
        "BenchmarkTest00396",
        "BenchmarkTest00558",
        "BenchmarkTest00814",
    ),
    (
        "BenchmarkTest00013",
        "BenchmarkTest00047",
        "BenchmarkTest00146",
        "BenchmarkTest00380",
        "BenchmarkTest00644",
        "BenchmarkTest00147",
        "BenchmarkTest00282",
        "BenchmarkTest00379",
        "BenchmarkTest00544",
        "BenchmarkTest00647",
    ),
    (
        "BenchmarkTest00008",
        "BenchmarkTest00043",
        "BenchmarkTest00100",
        "BenchmarkTest00337",
        "BenchmarkTest00429",
        "BenchmarkTest00052",
        "BenchmarkTest00107",
        "BenchmarkTest00190",
        "BenchmarkTest00432",
        "BenchmarkTest00592",
    ),
)
CASE_IDS = tuple(case_id for batch in BATCHES for case_id in batch)
SINK_WINDOWS = {
    "BenchmarkTest00001": (71, 72),
    "BenchmarkTest00218": (91, 112),
    "BenchmarkTest00359": (50, 63),
    "BenchmarkTest00619": (45, 72),
    "BenchmarkTest00783": (68, 82),
    "BenchmarkTest00063": (71, 78),
    "BenchmarkTest00134": (53, 75),
    "BenchmarkTest00217": (62, 94),
    "BenchmarkTest00784": (72, 96),
    "BenchmarkTest00862": (45, 65),
    "BenchmarkTest00006": (62, 69),
    "BenchmarkTest00077": (68, 102),
    "BenchmarkTest00294": (55, 75),
    "BenchmarkTest00495": (43, 71),
    "BenchmarkTest00815": (43, 89),
    "BenchmarkTest00051": (46, 63),
    "BenchmarkTest00305": (54, 99),
    "BenchmarkTest00396": (49, 70),
    "BenchmarkTest00558": (60, 87),
    "BenchmarkTest00814": (72, 94),
    "BenchmarkTest00013": (45, 56),
    "BenchmarkTest00047": (43, 73),
    "BenchmarkTest00146": (43, 59),
    "BenchmarkTest00380": (48, 68),
    "BenchmarkTest00644": (45, 52),
    "BenchmarkTest00147": (53, 65),
    "BenchmarkTest00282": (43, 57),
    "BenchmarkTest00379": (47, 70),
    "BenchmarkTest00544": (60, 73),
    "BenchmarkTest00647": (45, 51),
    "BenchmarkTest00008": (52, 58),
    "BenchmarkTest00043": (46, 54),
    "BenchmarkTest00100": (66, 85),
    "BenchmarkTest00337": (53, 70),
    "BenchmarkTest00429": (46, 65),
    "BenchmarkTest00052": (46, 59),
    "BenchmarkTest00107": (67, 94),
    "BenchmarkTest00190": (51, 73),
    "BenchmarkTest00432": (46, 62),
    "BenchmarkTest00592": (61, 95),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 6) if b else None


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    fpr = _ratio(fp, fp + tn)
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "accuracy": _ratio(tp + tn, tp + fp + tn + fn),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "balanced_accuracy": (
            round((recall + specificity) / 2, 6) if recall is not None and specificity is not None else None
        ),
        "owasp_mini_score": round(100 * (recall - fpr), 2) if recall is not None and fpr is not None else None,
    }


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _source_root(benchmark: Path) -> Path:
    return benchmark / "src" / "main" / "java" / "org" / "owasp" / "benchmark"


def _sources(benchmark: Path) -> tuple[dict[str, SourceUnit], list[SourceUnit]]:
    root = _source_root(benchmark)
    cases = {
        case_id: SourceUnit(
            case_id=case_id,
            path=f"testcode/{case_id}.java",
            content=(root / "testcode" / f"{case_id}.java").read_text(encoding="utf-8"),
        )
        for case_id in CASE_IDS
    }
    support = [
        SourceUnit(
            case_id=f"helper:{path.stem}",
            path=f"helpers/{path.name}",
            content=path.read_text(encoding="utf-8"),
        )
        for path in sorted((root / "helpers").glob("*.java"))
    ]
    property_file = benchmark / "src" / "main" / "resources" / "thing.properties"
    if property_file.exists():
        support.append(
            SourceUnit(
                case_id="resource:thing.properties",
                path="resources/thing.properties",
                content=property_file.read_text(encoding="utf-8"),
            )
        )
    return cases, support


def _selection(cases: dict[str, SourceUnit], support: list[SourceUnit]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "profile": "competition-40x3",
        "locked_at": _now(),
        "selection_rule": "40 fixed cases: each target CWE has five positive and five negative gold cases",
        "gold_in_prompt": False,
        "excluded_inputs": ["expectedresults-1.2.csv", "scorecard/", "results/", "README and solutions"],
        "batches": [list(batch) for batch in BATCHES],
        "cases": [
            {"case_id": item.case_id, "path": item.path, "sha256": item.sha256, "bytes": len(item.content.encode())}
            for item in cases.values()
        ],
        "support_files": [
            {"path": item.path, "sha256": item.sha256, "bytes": len(item.content.encode())} for item in support
        ],
    }
    payload["selection_sha256"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


def _settings(api_key: str) -> Settings:
    return Settings(
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
        model_reasoning_effort="max",
        model_thinking_enabled=True,
        model_max_output_tokens=32_768,
        model_max_attempts=1,
        max_model_calls=len(BATCHES) * REPETITIONS,
        model_timeout_seconds=180,
    )


async def predict(benchmark: Path, report: Path) -> None:
    if BoundedSourceReviewAgent is None:
        raise SystemExit(
            "The legacy bounded specialist was retired after v0.7.1. "
            "Use evaluate_comprehensive_public.py --arm v071 or --arm v080; "
            "the direct and integrated 40-case compatibility drivers remain available."
        )
    api_key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required")
    if (report / "raw" / "sealed-predictions.json").exists():
        raise SystemExit("sealed formal predictions already exist")
    cases, support = _sources(benchmark)
    selection = _selection(cases, support)
    _json(report / "selection-manifest.json", selection)
    gateway = QwenGateway(_settings(api_key))
    agent = BoundedSourceReviewAgent(gateway)
    all_runs: list[dict[str, Any]] = []
    started_at = _now()
    try:
        for repetition in range(1, REPETITIONS + 1):
            rep_predictions: list[dict[str, Any]] = []
            for batch_number, batch in enumerate(BATCHES, 1):
                run_id = f"formal40-r{repetition}-b{batch_number}-{uuid4()}"
                before = len(gateway.provider_attempts)
                try:
                    output, meta = await agent.review(
                        [cases[case_id] for case_id in batch], support_files=support, run_id=run_id
                    )
                except ModelGatewayError as exc:
                    attempts = gateway.provider_attempts[before:]
                    _json(
                        report / "raw" / f"repetition-{repetition}" / f"batch-{batch_number}-failure.json",
                        {
                            "run_id": run_id,
                            "error_type": type(exc).__name__,
                            "error_summary": str(exc)[:500],
                            "provider_attempts": len(attempts),
                            "failed_at": _now(),
                        },
                    )
                    raise
                attempts = gateway.provider_attempts_for(run_id)
                predictions = [item.model_dump(mode="json") for item in output.predictions]
                rep_predictions.extend(predictions)
                run = {
                    "run_id": run_id,
                    "repetition": repetition,
                    "batch": batch_number,
                    "case_ids": list(batch),
                    "model_id": meta.model_id,
                    "response_sha256": meta.response_sha256,
                    "duration_ms": meta.duration_ms,
                    "provider_attempt_count": len(attempts),
                    "successful_provider_requests": sum(item.succeeded for item in attempts),
                    "failed_provider_requests": sum(not item.succeeded for item in attempts),
                    "input_tokens": sum(item.usage.input_tokens for item in attempts),
                    "output_tokens": sum(item.usage.output_tokens for item in attempts),
                    "predictions": predictions,
                }
                all_runs.append(run)
                _json(report / "raw" / f"repetition-{repetition}" / f"batch-{batch_number}.json", run)
            _json(
                report / "raw" / f"repetition-{repetition}" / "predictions.json",
                {"repetition": repetition, "predictions": rep_predictions, "sealed_at": _now()},
            )
            print(
                f"[competition-40x3] completed repetition {repetition}/{REPETITIONS}",
                file=sys.stderr,
                flush=True,
            )
    finally:
        await gateway.close()
    input_tokens = sum(run["input_tokens"] for run in all_runs)
    output_tokens = sum(run["output_tokens"] for run in all_runs)
    usage = {
        "provider_requests": sum(run["provider_attempt_count"] for run in all_runs),
        "successful_provider_requests": sum(run["successful_provider_requests"] for run in all_runs),
        "failed_provider_requests": sum(run["failed_provider_requests"] for run in all_runs),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "total_latency_ms": sum(run["duration_ms"] for run in all_runs),
        "estimated_cost_upper_bound_usd": round(input_tokens * 0.14 / 1_000_000 + output_tokens * 0.28 / 1_000_000, 8),
        "pricing_source": "https://api-docs.deepseek.com/quick_start/pricing",
        "note": "Cache-miss upper-bound estimate; provider-reported tokens, not an invoice.",
    }
    sealed = {
        "schema_version": "1.0",
        "profile": "competition-40x3",
        "started_at": started_at,
        "sealed_at": _now(),
        "selection_sha256": selection["selection_sha256"],
        "model": {"id": MODEL_ID, "reasoning_effort": "max", "max_output_tokens": 32_768},
        "runs": all_runs,
        "usage": usage,
    }
    _json(report / "raw" / "sealed-predictions.json", sealed)
    print(json.dumps({"sealed": str(report / "raw" / "sealed-predictions.json"), "usage": usage}))


def _gold(benchmark: Path) -> tuple[dict[str, dict[str, Any]], str]:
    path = benchmark / "expectedresults-1.2.csv"
    result: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(line for line in stream if not line.startswith("#")):
            if len(row) == 4 and row[0] in CASE_IDS:
                result[row[0]] = {
                    "case_id": row[0],
                    "category": row[1],
                    "gold_vulnerable": row[2].lower() == "true",
                    "cwe": int(row[3]),
                }
    if set(result) != set(CASE_IDS):
        raise ValueError("gold CSV does not cover the locked selection")
    return result, _sha(path)


def _score_rep(
    predictions: list[dict[str, Any]], gold: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_id = {item["case_id"]: item for item in predictions}
    if set(by_id) != set(CASE_IDS) or len(by_id) != len(predictions):
        raise ValueError("repetition predictions do not match the locked 40 cases")
    tp = fp = tn = fn = evidence = positive_lines = positive_count = location_hits = true_positives = 0
    rows: list[dict[str, Any]] = []
    for case_id in CASE_IDS:
        expected, predicted = gold[case_id], by_id[case_id]
        matched = bool(predicted["vulnerable"] and predicted.get("cwe") == expected["cwe"])
        if expected["gold_vulnerable"] and matched:
            verdict, tp = "TP", tp + 1
            true_positives += 1
        elif expected["gold_vulnerable"]:
            verdict, fn = "FN", fn + 1
        elif matched:
            verdict, fp = "FP", fp + 1
        else:
            verdict, tn = "TN", tn + 1
        bound = bool(predicted.get("evidence_path") and predicted.get("evidence_sha256"))
        evidence += int(bound)
        if predicted["vulnerable"]:
            positive_count += 1
            positive_lines += int(isinstance(predicted.get("sink_line"), int))
        window = SINK_WINDOWS[case_id]
        location_hit = bool(
            verdict == "TP"
            and isinstance(predicted.get("sink_line"), int)
            and window[0] <= predicted["sink_line"] <= window[1]
        )
        location_hits += int(location_hit)
        rows.append(
            {
                "case_id": case_id,
                "category": expected["category"],
                "gold_cwe": expected["cwe"],
                "gold_vulnerable": expected["gold_vulnerable"],
                "predicted_vulnerable": predicted["vulnerable"],
                "predicted_cwe": predicted.get("cwe"),
                "verdict": verdict,
                "confidence": predicted["confidence"],
                "sink_line": predicted.get("sink_line"),
                "sink_window": list(window),
                "location_hit": location_hit,
                "evidence_bound": bound,
            }
        )
    metrics = _metrics(tp, fp, tn, fn)
    metrics.update(
        {
            "case_count": len(CASE_IDS),
            "evidence_binding_rate": _ratio(evidence, len(CASE_IDS)),
            "positive_location_presence_rate": _ratio(positive_lines, positive_count),
            "true_positive_sink_window_rate": _ratio(location_hits, true_positives),
        }
    )
    return rows, metrics


def score(benchmark: Path, report: Path) -> None:
    sealed_path = report / "raw" / "sealed-predictions.json"
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    gold_loaded_at = _now()
    gold, gold_sha = _gold(benchmark)
    per_rep: list[dict[str, Any]] = []
    prediction_bits: dict[str, list[str]] = {case_id: [] for case_id in CASE_IDS}
    total = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    category_counts: dict[str, dict[str, int]] = {}
    error_events: list[dict[str, Any]] = []
    for repetition in range(1, REPETITIONS + 1):
        rep = json.loads((report / "raw" / f"repetition-{repetition}" / "predictions.json").read_text(encoding="utf-8"))
        rows, metrics = _score_rep(rep["predictions"], gold)
        for row in rows:
            prediction_bits[row["case_id"]].append(f"{row['predicted_vulnerable']}:{row['predicted_cwe']}")
            counts = category_counts.setdefault(row["category"], {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
            counts[row["verdict"].lower()] += 1
            if row["verdict"] in {"FP", "FN"}:
                error_events.append({"repetition": repetition, **row})
        for key in total:
            total[key] += metrics["confusion_matrix"][key]
        _json(report / "scoring" / f"repetition-{repetition}.json", {"metrics": metrics, "cases": rows})
        per_rep.append({"repetition": repetition, **metrics})
    aggregate = _metrics(total["tp"], total["fp"], total["tn"], total["fn"])
    unstable_cases = [case_id for case_id, bits in prediction_bits.items() if len(set(bits)) > 1]
    per_category = {category: _metrics(**counts) for category, counts in sorted(category_counts.items())}
    aggregate.update(
        {
            "profile": "competition-40x3",
            "unique_cases": len(CASE_IDS),
            "total_case_evaluations": len(CASE_IDS) * REPETITIONS,
            "repetitions": REPETITIONS,
            "case_level_full_agreement_rate": _ratio(
                sum(len(set(bits)) == 1 for bits in prediction_bits.values()), len(CASE_IDS)
            ),
            "unstable_cases": unstable_cases,
            "error_event_count": len(error_events),
            "accuracy_wilson_95": _wilson(total["tp"] + total["tn"], sum(total.values())),
            "recall_wilson_95": _wilson(total["tp"], total["tp"] + total["fn"]),
            "per_category": per_category,
            "per_repetition": per_rep,
            "prediction_sha256": _sha(sealed_path),
            "gold_sha256": gold_sha,
            "prediction_sealed_at": sealed["sealed_at"],
            "gold_loaded_at": gold_loaded_at,
            "gold_loaded_after_prediction": gold_loaded_at >= sealed["sealed_at"],
            "usage": sealed["usage"],
        }
    )
    _json(report / "gold" / "gold-labels.json", {"source_sha256": gold_sha, "cases": gold})
    _json(report / "scoring" / "metrics.json", aggregate)
    _json(report / "scoring" / "error-analysis.json", {"errors": error_events, "unstable_cases": unstable_cases})
    manifest = {
        "report_schema": "1.0",
        "product_version": "0.7.1",
        "profile": "competition-40x3",
        "generated_at": _now(),
        "host": platform.platform(),
        "python": sys.version.split()[0],
        "git_commit": os.environ.get("SECMIND_EVAL_GIT_COMMIT"),
        "dirty_tree": os.environ.get("SECMIND_EVAL_GIT_DIRTY", "").lower() == "true",
        "dataset": {"name": "OWASP BenchmarkJava 1.2", "unique_cases": 40, "gold_sha256": gold_sha},
        "model": {"provider": "DeepSeek", "id": MODEL_ID, "reasoning_effort": "max", "max_output_tokens": 32_768},
        "usage": sealed["usage"],
        "gold_access_policy": "All predictions were sealed before the score-only process loaded the gold CSV.",
        "limitations": [
            "Restricted to four Java vulnerability categories, not all BenchmarkJava categories.",
            "Public benchmark may be represented in model training data.",
            "Evaluates the bounded source-review specialist, not sandbox/recovery/concurrency release gates.",
        ],
    }
    _json(report / "experiment-manifest.json", manifest)
    cm = aggregate["confusion_matrix"]
    rows_md = "\n".join(
        f"| {item['repetition']} | {item['confusion_matrix']['tp']} | {item['confusion_matrix']['fp']} | "
        f"{item['confusion_matrix']['tn']} | {item['confusion_matrix']['fn']} | {item['precision']} | "
        f"{item['recall']} | {item['f1']} | {item['accuracy']} |"
        for item in per_rep
    )
    errors_md = "\n".join(
        f"| {item['repetition']} | {item['case_id']} | {item['category']} | {item['verdict']} | "
        f"{item['predicted_cwe'] or '-'} | {item['confidence']} |"
        for item in error_events
    )
    categories_md = "\n".join(
        f"| {category} | {values['precision']} | {values['recall']} | {values['f1']} | {values['accuracy']} |"
        for category, values in per_category.items()
    )
    markdown = f"""# SecMind v0.7 正式 40×3 DeepSeek 实战评测

## 技术摘要

DeepSeek V4 Flash 以 `max` 推理强度完成 40 个固定金标用例、3 次独立重复，共 120 次判定。
聚合结果为 TP={cm["tp"]}、FP={cm["fp"]}、TN={cm["tn"]}、FN={cm["fn"]}，
Precision={aggregate["precision"]}、Recall={aggregate["recall"]}、F1={aggregate["f1"]}、
Accuracy={aggregate["accuracy"]}。40 题跨重复完全一致率为 {aggregate["case_level_full_agreement_rate"]}。

## 三轮结果

| 轮次 | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
{rows_md}

## 分类别表现

| 类别 | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|
{categories_md}

## 误判与跨轮波动

| 轮次 | Case | 类别 | 错误 | 预测 CWE | 置信度 |
|---:|---|---|---|---:|---:|
{errors_md}

{len(unstable_cases)} 个不稳定用例为：{", ".join(unstable_cases)}。主要弱点集中在列表索引/删除后的安全值跟踪、
固定分支可达性，以及 Runtime.exec 环境参数与命令参数的数据流语义。Accuracy 的 Wilson 95%
区间为 {aggregate["accuracy_wilson_95"]}，Recall 区间为 {aggregate["recall_wilson_95"]}。

## 真实调用与成本

正式评测发起 {sealed["usage"]["provider_requests"]} 次 Provider 请求（成功
{sealed["usage"]["successful_provider_requests"]}、失败
{sealed["usage"]["failed_provider_requests"]}），Provider 计量输入
{sealed["usage"]["input_tokens"]}、输出 {sealed["usage"]["output_tokens"]}、合计
{sealed["usage"]["total_tokens"]} Token；串行总延迟 {sealed["usage"]["total_latency_ms"]} ms。
按全部输入未命中缓存估算费用上限为
${sealed["usage"]["estimated_cost_upper_bound_usd"]:.8f}，不是账单金额。

## 范围、数据与评分

40 题覆盖 CWE-22、78、79、89，每类 5 阳性和 5 阴性。每轮均读取同一锁定源码及完整
Benchmark helpers，但不读取金标、scorecard 或历史答案。每题只有 `vulnerable=true` 且 CWE
与目标类别匹配才计为阳性；预测封存后由无模型调用的评分进程读取
`expectedresults-1.2.csv`。

## 可信性与限制

这是公开 Java 基准上四个类别的正式子集，不是完整 2,740 题或全语言总成绩；公开题可能存在
训练数据记忆。它验证了 v0.7 受限源码审计专家的真实模型检测、跨文件推理、证据绑定和重复
稳定性，但不替代 LangGraph 恢复、Broker、Runner、安全策略和并发门禁。

## 下一步

- 加入未公开或扰动后的同构样本，区分真实泛化与基准记忆。
- 将 Java 专家接入受控 DAG 节点，并与 Semgrep/OSV 证据做确定性融合。
- 用相同 40×3 协议比较 DeepSeek 与离线工具链的边际召回、误报和成本。
"""
    (report / "README.md").write_text(markdown, encoding="utf-8")
    table = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in (
                item["repetition"],
                item["confusion_matrix"]["tp"],
                item["confusion_matrix"]["fp"],
                item["confusion_matrix"]["tn"],
                item["confusion_matrix"]["fn"],
                item["f1"],
                item["accuracy"],
            )
        )
        + "</tr>"
        for item in per_rep
    )
    report_html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>SecMind v0.7 40×3 实战评测</title>
  <style>
    body {{ font: 16px/1.65 system-ui; max-width: 1000px; margin: auto; padding: 32px }}
    .k {{ font-size: 1.8rem; font-weight: 700 }}
    .grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 12px }}
    .card {{ border: 1px solid #8885; border-radius: 10px; padding: 14px }}
    table {{ width: 100%; border-collapse: collapse }}
    td, th {{ padding: 9px; border-bottom: 1px solid #8885 }}
  </style>
</head>
<body>
  <h1>SecMind v0.7 正式 40×3 DeepSeek 实战评测</h1>
  <h2>技术摘要</h2>
  <p>120 次金标判定：TP={cm["tp"]}、FP={cm["fp"]}、TN={cm["tn"]}、FN={cm["fn"]}。</p>
  <div class="grid">
    <div class="card">Precision<div class="k">{aggregate["precision"]}</div></div>
    <div class="card">Recall<div class="k">{aggregate["recall"]}</div></div>
    <div class="card">F1<div class="k">{aggregate["f1"]}</div></div>
    <div class="card">Accuracy<div class="k">{aggregate["accuracy"]}</div></div>
  </div>
  <h2>三轮结果</h2>
  <table><thead><tr><th>轮次</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th>
  <th>F1</th><th>Accuracy</th></tr></thead><tbody>{table}</tbody></table>
  <h2>调用与成本</h2>
  <p>{sealed["usage"]["provider_requests"]} 次真实请求，{sealed["usage"]["total_tokens"]} Token，
  费用上限估算 ${sealed["usage"]["estimated_cost_upper_bound_usd"]:.8f}。</p>
  <h2>边界</h2>
  <p>公开 BenchmarkJava 四类 40 题，不代表完整基准或全系统发布门禁；
  完整审计材料见同目录 JSON 与哈希清单。</p>
</body>
</html>"""
    (report / "report.html").write_text(report_html, encoding="utf-8")
    targets = sorted(path for path in report.rglob("*") if path.is_file() and path.name != "hashes.sha256")
    (report / "hashes.sha256").write_text(
        "".join(f"{_sha(path)}  {path.relative_to(report).as_posix()}\n" for path in targets), encoding="utf-8"
    )
    print(json.dumps({"report": str(report / "README.md"), "metrics": aggregate}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="SecMind competition-profile 40x3 live DeepSeek evaluation")
    parser.add_argument("phase", choices=("predict", "score"))
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.phase == "predict":
        asyncio.run(predict(args.benchmark_root.resolve(), args.report_dir.resolve()))
    else:
        score(args.benchmark_root.resolve(), args.report_dir.resolve())


if __name__ == "__main__":
    main()
