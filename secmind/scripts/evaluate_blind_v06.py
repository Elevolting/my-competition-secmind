from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from blind_benchmark_common import load_manifest, load_units, now, prediction_commitment, write_json

from secmind.config import Settings
from secmind.runtime import build_runtime
from secmind.schemas import AttachmentRef, RunStatus, TaskRequest

MODEL_ID = "deepseek-v4-flash"
BASE_URL = "https://api.deepseek.com"
TERMINAL = {
    RunStatus.COMPLETED,
    RunStatus.PARTIAL,
    RunStatus.FAILED,
    RunStatus.DENIED,
    RunStatus.RECOVERY_REQUIRED,
    RunStatus.CANCELLED,
}
CONFIDENCE = {"HIGH": 0.95, "MEDIUM": 0.75, "LOW": 0.4, "UNKNOWN": 0.0}


def _settings(root: Path, api_key: str) -> Settings:
    return Settings(
        env="evaluation",
        runtime_role="embedded",
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
        unsafe_development_tools=True,
        database_url=f"sqlite:///{(root / 'v06-agent.db').as_posix()}",
        input_root=root / "inputs",
        upload_root=root / "uploads",
        run_root=root / "runs",
        artifact_root=root / "artifacts",
        max_runtime_seconds=1800,
        max_steps=100,
        max_tool_calls=100,
        max_model_calls=100,
        max_provider_requests=100,
        max_input_tokens=10_000_000,
        max_output_tokens=3_000_000,
        max_cost_units=60,
        max_files=20_000,
    )


def _stage(input_root: Path, manifest: dict[str, Any], destination: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for item in [*manifest["cases"], *manifest["support_files"]]:
        source = input_root / item["path"]
        target = destination / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        hashes[item["path"]] = item["sha256"]
    return hashes


def _predictions(state: Any, manifest: dict[str, Any], *, model_completed: bool) -> list[dict[str, Any]]:
    report_findings = state.report.findings if state.report is not None else []
    by_case: dict[str, list[Any]] = {item["case_id"]: [] for item in manifest["cases"]}
    for finding in report_findings:
        case_id = Path(finding.path).stem
        if case_id in by_case and finding.rule_id.startswith("CWE-"):
            by_case[case_id].append(finding)
    predictions: list[dict[str, Any]] = []
    for item in manifest["cases"]:
        case_id = item["case_id"]
        path = item["path"]
        candidates = sorted(
            by_case[case_id],
            key=lambda finding: (-CONFIDENCE[finding.confidence], finding.line or 0, finding.rule_id),
        )
        selected = candidates[0] if candidates else None
        if selected is None:
            predictions.append(
                {
                    "case_id": case_id,
                    "vulnerable": False if model_completed else None,
                    "cwe": None,
                    "sink_line": None,
                    "confidence": 0.0,
                    "evidence_path": path,
                    "evidence_sha256": item["sha256"],
                    "evidence_excerpt": "",
                    "rationale_summary": (
                        "No verified finding survived the integrated Agent."
                        if model_completed
                        else "Integrated model source review did not complete."
                    ),
                    "operational_error": None if model_completed else "model_source_review_incomplete",
                }
            )
            continue
        try:
            cwe = int(selected.rule_id.removeprefix("CWE-"))
        except ValueError:
            cwe = None
        predictions.append(
            {
                "case_id": case_id,
                "vulnerable": True,
                "cwe": cwe,
                "sink_line": selected.line,
                "confidence": CONFIDENCE[selected.confidence],
                "evidence_path": path,
                "evidence_sha256": item["sha256"],
                "evidence_excerpt": str(selected.raw.get("evidence_excerpt", ""))[:400],
                "rationale_summary": selected.description[:500],
                "operational_error": None,
            }
        )
    return predictions


async def predict(input_root: Path, output: Path, api_key: str, repetitions: int) -> None:
    sealed_path = output / "raw" / "sealed-predictions.json"
    if sealed_path.exists():
        raise SystemExit("sealed v0.6 predictions already exist")
    manifest = load_manifest(input_root / "blind-manifest.json")
    load_units(input_root, manifest)
    with tempfile.TemporaryDirectory(prefix="secmind-v06-blind-") as temporary:
        root = Path(temporary)
        settings = _settings(root, api_key)
        settings.prepare_directories()
        service, gateway = build_runtime(settings)
        runs: list[dict[str, Any]] = []
        started_at = now()
        try:
            await service.startup()
            for repetition in range(1, repetitions + 1):
                attachment = f"blind-v06-r{repetition}-{uuid4()}"
                _stage(input_root, manifest, settings.input_root / attachment)
                run_id = service.submit(
                    TaskRequest(
                        client_request_id=f"blind-v06-{repetition}-{uuid4()}",
                        objective=(
                            "对密封 Java 源码执行深度跨文件安全审计，使用所有已批准能力和 DeepSeek "
                            "源码专家，输出经过 Evidence Verifier 验证的结论。"
                        ),
                        attachments=[AttachmentRef(ref=attachment)],
                        target_scope=["."],
                        constraints=["只读静态分析", "禁止网络工具", "不得读取评分答案"],
                        expected_outputs=["security_report", "evidence", "coverage_limitations"],
                        autonomy_policy="automatic",
                    )
                )
                started = time.monotonic()
                queue_error = None
                async with asyncio.timeout(1800):
                    while True:
                        state = service.state(run_id)
                        queue_status, _lease, queue_error = service.coordinator.job_snapshot(run_id)
                        if (
                            state.status in TERMINAL
                            and state.report is not None
                            and queue_status in {"completed", "cancelled", "recovery_required"}
                        ):
                            break
                        await asyncio.sleep(0.05)
                events = service.ledger.events(run_id)
                database = service._replay_database_snapshot(run_id)
                model_completed = any(item.decision == "model_source_review_completed" for item in state.decisions)
                predictions = _predictions(state, manifest, model_completed=model_completed)
                run = {
                    "run_id": run_id,
                    "repetition": repetition,
                    "status": state.status.value,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "queue_error": queue_error,
                    "model_completed": model_completed,
                    "provider_usage": {
                        "provider_requests": len(database["models"]),
                        "input_tokens": sum(item["input_tokens"] for item in database["models"]),
                        "output_tokens": sum(item["output_tokens"] for item in database["models"]),
                    },
                    "provider_attempts": database["models"],
                    "model_calls_used": state.budget.model_calls_used,
                    "tool_calls_used": state.budget.tool_calls_used,
                    "decision_summaries": [item.model_dump(mode="json") for item in state.decisions],
                    "finding_count": len(state.findings),
                    "reported_finding_count": len(state.report.findings),
                    "claim_count": len(state.claims),
                    "verified_claim_count": sum(item.status == "verified" for item in state.verification_results),
                    "evidence_count": len(state.evidence),
                    "ledger_event_count": len(events),
                    "ledger_head_hash": events[-1].hash if events else None,
                    "ledger_valid": service.ledger.verify(run_id),
                    "limitations": state.report.limitations,
                    "last_error": state.last_error,
                    "predictions": predictions,
                }
                runs.append(run)
                write_json(output / "raw" / f"repetition-{repetition}" / "agent-run.json", run)
                write_json(
                    output / "raw" / f"repetition-{repetition}" / "predictions.json",
                    {"repetition": repetition, "predictions": predictions, "sealed_at": now()},
                )
        finally:
            await service.shutdown()
            await gateway.close()

    usage = {
        "provider_requests": sum(run["provider_usage"]["provider_requests"] for run in runs),
        "input_tokens": sum(run["provider_usage"]["input_tokens"] for run in runs),
        "output_tokens": sum(run["provider_usage"]["output_tokens"] for run in runs),
        "end_to_end_latency_ms": sum(run["duration_ms"] for run in runs),
    }
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    sealed = {
        "schema_version": "1.0",
        "protocol": manifest["protocol"],
        "arm": "A-v0.6-integrated-secmind-agent",
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
    parser = argparse.ArgumentParser(description="Run the integrated SecMind v0.6 blind benchmark arm")
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
