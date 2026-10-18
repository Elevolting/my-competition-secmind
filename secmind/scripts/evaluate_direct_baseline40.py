from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import evaluate_live_benchmark40 as formal

import secmind.live_source_review as source_review
from secmind.live_source_review import SourceUnit
from secmind.llm import ModelGatewayError, QwenGateway

SourceReviewOutput = getattr(source_review, "SourceReviewOutput", None)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _render(cases: list[SourceUnit], support: list[SourceUnit]) -> str:
    blocks = [
        "Directly audit every CASE below for a security vulnerability. SUPPORT files are context only. "
        "Return one prediction for every CASE. Gold labels are not included."
    ]
    for kind, units in (("SUPPORT", support), ("CASE", cases)):
        for unit in units:
            numbered = "\n".join(f"{index:04d}: {line}" for index, line in enumerate(unit.content.splitlines(), 1))
            blocks.append(
                f"<{kind} id={unit.case_id!r} path={unit.path!r} sha256={unit.sha256!r}>\n{numbered}\n</{kind}>"
            )
    return "\n\n".join(blocks)


async def predict(benchmark: Path, report: Path) -> None:
    if SourceReviewOutput is None:
        raise SystemExit(
            "The legacy 40-case output contract was retired after v0.7.1. "
            "Use evaluate_comprehensive_public.py --arm direct for the maintained direct baseline."
        )
    api_key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required")
    sealed_path = report / "raw" / "sealed-predictions.json"
    if sealed_path.exists():
        raise SystemExit("sealed direct-baseline predictions already exist")

    cases, support = formal._sources(benchmark)
    selection = formal._selection(cases, support)
    selection.update(
        {
            "profile": "direct-model-40x3",
            "arm": "D0-direct-raw",
            "prompt_family": "generic-direct-source-audit-v1",
        }
    )
    selection["selection_sha256"] = hashlib.sha256(
        json.dumps(selection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _json(report / "selection-manifest.json", selection)

    gateway = QwenGateway(formal._settings(api_key))
    all_runs: list[dict[str, Any]] = []
    started_at = _now()
    try:
        for repetition in range(1, formal.REPETITIONS + 1):
            rep_predictions: list[dict[str, Any]] = []
            for batch_number, batch in enumerate(formal.BATCHES, 1):
                run_id = f"direct40-r{repetition}-b{batch_number}-{uuid4()}"
                units = [cases[case_id] for case_id in batch]
                try:
                    output, meta = await gateway.structured(
                        role="planner",
                        system_prompt=(
                            "You are DeepSeek V4 Flash used directly without an agent, tools, memory, reflection, "
                            "or a verifier. Audit the supplied Java source and return only the requested JSON."
                        ),
                        user_prompt=_render(units, support),
                        output_model=SourceReviewOutput,
                        prompt_version="direct-deepseek-java-audit-v1",
                        run_id=run_id,
                    )
                    predictions = [item.model_dump(mode="json") for item in output.predictions]
                    returned = {item["case_id"] for item in predictions}
                    if returned != set(batch) or len(returned) != len(predictions):
                        raise ModelGatewayError("direct output did not contain each case exactly once")
                    failure: dict[str, Any] | None = None
                except Exception as exc:
                    # Operational failures remain in the intention-to-test denominator.
                    failure = {"type": type(exc).__name__, "summary": str(exc)[:300]}
                    predictions = [
                        {
                            "case_id": unit.case_id,
                            "vulnerable": False,
                            "cwe": None,
                            "sink_line": None,
                            "confidence": 0.0,
                            "evidence_path": unit.path,
                            "evidence_sha256": unit.sha256,
                            "evidence_excerpt": "",
                            "rationale_summary": "No valid direct-model prediction was returned.",
                        }
                        for unit in units
                    ]
                    meta = None
                attempts = gateway.provider_attempts_for(run_id)
                run = {
                    "run_id": run_id,
                    "arm": "D0-direct-raw",
                    "repetition": repetition,
                    "batch": batch_number,
                    "case_ids": list(batch),
                    "model_id": meta.model_id if meta is not None else formal.MODEL_ID,
                    "response_sha256": meta.response_sha256 if meta is not None else None,
                    "duration_ms": sum(item.duration_ms for item in attempts),
                    "provider_attempt_count": len(attempts),
                    "successful_provider_requests": sum(item.succeeded for item in attempts),
                    "failed_provider_requests": sum(not item.succeeded for item in attempts),
                    "input_tokens": sum(item.usage.input_tokens for item in attempts),
                    "output_tokens": sum(item.usage.output_tokens for item in attempts),
                    "failure": failure,
                    "predictions": predictions,
                }
                all_runs.append(run)
                rep_predictions.extend(predictions)
                _json(report / "raw" / f"repetition-{repetition}" / f"batch-{batch_number}.json", run)
            _json(
                report / "raw" / f"repetition-{repetition}" / "predictions.json",
                {"repetition": repetition, "predictions": rep_predictions, "sealed_at": _now()},
            )
            print(
                f"[direct-model-40x3] completed repetition {repetition}/{formal.REPETITIONS}",
                file=sys.stderr,
                flush=True,
            )
    finally:
        await gateway.close()

    input_tokens = sum(run["input_tokens"] for run in all_runs)
    output_tokens = sum(run["output_tokens"] for run in all_runs)
    usage = {
        "provider_requests": sum(run["provider_attempt_count"] for run in all_runs),
        "provider_attempts": sum(run["provider_attempt_count"] for run in all_runs),
        "successful_provider_requests": sum(run["successful_provider_requests"] for run in all_runs),
        "failed_provider_requests": sum(run["failed_provider_requests"] for run in all_runs),
        "failed_batches": sum(run["failure"] is not None for run in all_runs),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "total_latency_ms": sum(run["duration_ms"] for run in all_runs),
        "estimated_cost_upper_bound_usd": round(input_tokens * 0.14 / 1_000_000 + output_tokens * 0.28 / 1_000_000, 8),
        "pricing_source": "https://api-docs.deepseek.com/quick_start/pricing",
        "note": "Cache-miss upper-bound estimate; provider usage, not an invoice.",
    }
    sealed = {
        "schema_version": "1.0",
        "profile": "direct-model-40x3",
        "arm": "D0-direct-raw",
        "started_at": started_at,
        "sealed_at": _now(),
        "selection_sha256": selection["selection_sha256"],
        "model": {"id": formal.MODEL_ID, "reasoning_effort": "max", "max_output_tokens": 32_768},
        "runs": all_runs,
        "usage": usage,
    }
    _json(sealed_path, sealed)
    print(json.dumps({"sealed": str(sealed_path), "usage": usage}, ensure_ascii=False))


def score(benchmark: Path, report: Path) -> None:
    formal.score(benchmark, report)
    manifest_path = report / "experiment-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "profile": "direct-model-40x3",
            "arm": "D0-direct-raw",
            "evaluation_target": "DeepSeek V4 Flash direct source audit without SecMind orchestration",
            "limitations": [
                "This is the direct-model control arm, not a SecMind Agent run.",
                "Restricted to four Java vulnerability categories and a public benchmark.",
                "The output schema is shared for parseability; there are no tools, memory, reflection, or verifier.",
            ],
        }
    )
    _json(manifest_path, manifest)
    metrics = json.loads((report / "scoring" / "metrics.json").read_text(encoding="utf-8"))
    cm = metrics["confusion_matrix"]
    readme = f"""# DeepSeek V4 Flash 直接模型 40×3 对照

本对照臂在与 SecMind bounded specialist 相同的 40 个 BenchmarkJava 用例、相同源码与 helpers、
相同模型、推理强度和结构化输出 Schema 下运行，但不使用 Agent 编排、工具、记忆、反思或证据验证器。

聚合结果：TP={cm["tp"]}、FP={cm["fp"]}、TN={cm["tn"]}、FN={cm["fn"]}；
Precision={metrics["precision"]}、Recall={metrics["recall"]}、F1={metrics["f1"]}、
Accuracy={metrics["accuracy"]}。三轮完全一致率={metrics["case_level_full_agreement_rate"]}。

真实 Provider 用量：{metrics["usage"]["provider_requests"]} 次请求（成功
{metrics["usage"]["successful_provider_requests"]}、失败
{metrics["usage"]["failed_provider_requests"]}），
{metrics["usage"]["total_tokens"]} Token，缓存未命中费用上限估算
${metrics["usage"]["estimated_cost_upper_bound_usd"]:.8f}。

预测在读取 `expectedresults-1.2.csv` 前封存；错误明细、逐轮结果和哈希见本目录。
这只是直接模型控制臂，不能单独代表完整 v0.7 产品效果。
"""
    (report / "README.md").write_text(readme, encoding="utf-8")
    targets = sorted(path for path in report.rglob("*") if path.is_file() and path.name != "hashes.sha256")
    (report / "hashes.sha256").write_text(
        "".join(f"{formal._sha(path)}  {path.relative_to(report).as_posix()}\n" for path in targets),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="DeepSeek direct-model 40x3 control arm")
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
