from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from blind_benchmark_common import batches, load_manifest, load_units, now, prediction_commitment, write_json

from secmind.config import Settings
from secmind.live_source_review import BoundedSourceReviewAgent, SourceReviewError, SourceUnit
from secmind.llm import ModelGatewayError, QwenGateway

MODEL_ID = "deepseek-v4-flash"
BASE_URL = "https://api.deepseek.com"


def _settings(api_key: str) -> Settings:
    return Settings(
        env="evaluation",
        demo_mode=False,
        model_mode="live",
        allow_live_models=True,
        max_model_tier=5.4,
        trusted_model_base_urls=BASE_URL,
        qwen_base_url=BASE_URL,
        qwen_api_key=api_key,
        planner_model=MODEL_ID,
        worker_model=MODEL_ID,
        fallback_model=MODEL_ID,
        embedding_model="text-embedding-v3",
        model_reasoning_effort="max",
        model_thinking_enabled=True,
        model_max_output_tokens=32_768,
        model_max_attempts=1,
        model_structured_repair_attempts=1,
        model_timeout_seconds=180,
        max_provider_requests=100,
        max_input_tokens=10_000_000,
        max_output_tokens=3_000_000,
        max_cost_units=60,
    )


def _failed_predictions(batch: list[SourceUnit], error: str) -> list[dict[str, Any]]:
    return [
        {
            "case_id": item.case_id,
            "vulnerable": None,
            "cwe": None,
            "sink_line": None,
            "confidence": 0.0,
            "evidence_path": item.path,
            "evidence_sha256": item.sha256,
            "evidence_excerpt": "",
            "rationale_summary": f"Operational failure: {error}",
            "operational_error": error,
        }
        for item in batch
    ]


async def predict(input_root: Path, output: Path, api_key: str, repetitions: int) -> None:
    sealed_path = output / "raw" / "sealed-predictions.json"
    if sealed_path.exists():
        raise SystemExit("sealed direct predictions already exist")
    manifest = load_manifest(input_root / "blind-manifest.json")
    cases, support = load_units(input_root, manifest)
    cases.sort(key=lambda item: item.path)
    support.sort(key=lambda item: item.path)
    gateway = QwenGateway(_settings(api_key))
    reviewer = BoundedSourceReviewAgent(gateway)
    runs: list[dict[str, Any]] = []
    started_at = now()
    try:
        for repetition in range(1, repetitions + 1):
            predictions: list[dict[str, Any]] = []
            for batch_number, batch in enumerate(batches(cases), 1):
                run_id = f"blind-direct-r{repetition}-b{batch_number}-{uuid4()}"
                started = time.monotonic()
                meta = None
                error = None
                try:
                    result, meta = await reviewer.review(batch, support_files=support, run_id=run_id)
                    batch_predictions = [item.model_dump(mode="json") for item in result.predictions]
                except (ModelGatewayError, SourceReviewError) as exc:
                    error = type(exc).__name__
                    batch_predictions = _failed_predictions(batch, error)
                attempts = gateway.provider_attempts_for(run_id)
                predictions.extend(batch_predictions)
                write_json(
                    output / "raw" / f"repetition-{repetition}" / f"batch-{batch_number}.json",
                    {
                        "run_id": run_id,
                        "repetition": repetition,
                        "batch": batch_number,
                        "case_ids": [item.case_id for item in batch],
                        "model_id": MODEL_ID,
                        "response_sha256": meta.response_sha256 if meta is not None else None,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "provider_attempts": [
                            {
                                "status_code": item.status_code,
                                "succeeded": item.succeeded,
                                "retryable": item.retryable,
                                "error_type": item.error_type,
                                "input_tokens": item.usage.input_tokens,
                                "output_tokens": item.usage.output_tokens,
                            }
                            for item in attempts
                        ],
                        "error": error,
                        "predictions": batch_predictions,
                    },
                )
            run = {"repetition": repetition, "predictions": predictions, "sealed_at": now()}
            runs.append(run)
            write_json(output / "raw" / f"repetition-{repetition}" / "predictions.json", run)
    finally:
        all_attempts = list(gateway.provider_attempts)
        await gateway.close()

    usage = {
        "provider_requests": len(all_attempts),
        "input_tokens": sum(item.usage.input_tokens for item in all_attempts),
        "output_tokens": sum(item.usage.output_tokens for item in all_attempts),
        "total_latency_ms": sum(item.duration_ms for item in all_attempts),
    }
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    sealed = {
        "schema_version": "1.0",
        "protocol": manifest["protocol"],
        "arm": "D-prompt-matched-direct-deepseek",
        "started_at": started_at,
        "sealed_at": now(),
        "input_bundle_sha256": manifest["input_bundle_sha256"],
        "model": {"id": MODEL_ID, "reasoning_effort": "max", "structured_repairs": 1},
        "repetitions": repetitions,
        "runs": runs,
        "usage": usage,
    }
    sealed["prediction_commitment_sha256"] = prediction_commitment(runs)
    write_json(sealed_path, sealed)
    print(json.dumps({"sealed": str(sealed_path), "usage": usage}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the prompt-matched direct DeepSeek blind control")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3, choices=(1, 2, 3))
    args = parser.parse_args()
    key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
    if not key:
        raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required")
    asyncio.run(predict(args.input_dir.resolve(), args.output_dir.resolve(), key, args.repetitions))


if __name__ == "__main__":
    main()
