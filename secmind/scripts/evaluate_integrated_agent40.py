from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import evaluate_live_benchmark40 as formal

from secmind.config import Settings
from secmind.runtime import build_runtime
from secmind.schemas import AttachmentRef, RunStatus, TaskRequest

TERMINAL = {
    RunStatus.COMPLETED,
    RunStatus.PARTIAL,
    RunStatus.FAILED,
    RunStatus.DENIED,
    RunStatus.RECOVERY_REQUIRED,
    RunStatus.CANCELLED,
}
CONFIDENCE = {"HIGH": 0.95, "MEDIUM": 0.75, "LOW": 0.4, "UNKNOWN": 0.0}


def _json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _settings(root: Path, api_key: str) -> Settings:
    return Settings(
        env="evaluation",
        runtime_role="embedded",
        demo_mode=False,
        model_mode="live",
        allow_live_models=True,
        max_model_tier=5.4,
        trusted_model_base_urls="https://api.deepseek.com",
        qwen_base_url="https://api.deepseek.com",
        qwen_api_key=api_key,
        planner_model="deepseek-v4-flash",
        worker_model="deepseek-v4-flash",
        fallback_model="deepseek-v4-flash",
        embedding_model="text-embedding-v3",
        model_reasoning_effort="max",
        model_thinking_enabled=True,
        model_max_output_tokens=32_768,
        model_max_attempts=1,
        model_structured_repair_attempts=1,
        model_timeout_seconds=180,
        unsafe_development_tools=True,
        database_url=f"sqlite:///{(root / 'integrated-agent.db').as_posix()}",
        input_root=root / "inputs",
        upload_root=root / "uploads",
        run_root=root / "runs",
        artifact_root=root / "artifacts",
        max_runtime_seconds=1800,
        max_steps=100,
        max_tool_calls=100,
        max_model_calls=200,
        max_provider_requests=200,
        max_input_tokens=5_000_000,
        max_output_tokens=1_000_000,
        max_cost_units=30.0,
        max_files=20_000,
    )


def _stage(benchmark: Path, destination: Path) -> tuple[dict[str, Any], dict[str, str]]:
    cases, support = formal._sources(benchmark)
    file_hashes: dict[str, str] = {}
    manifest_files: list[dict[str, Any]] = []
    for unit in [*cases.values(), *support]:
        target = destination / unit.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(unit.content, encoding="utf-8")
        file_hashes[unit.path] = unit.sha256
        manifest_files.append({"path": unit.path, "sha256": unit.sha256, "bytes": len(unit.content.encode("utf-8"))})
    canonical = json.dumps(manifest_files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "files": manifest_files,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "explicitly_excluded": ["expectedresults-1.2.csv", "scorecard", "results", "README", ".git"],
    }, file_hashes


def _predictions(state: Any, file_hashes: dict[str, str]) -> list[dict[str, Any]]:
    report_findings = state.report.findings if state.report is not None else []
    by_case: dict[str, list[Any]] = {case_id: [] for case_id in formal.CASE_IDS}
    for finding in report_findings:
        case_id = Path(finding.path).stem
        if case_id in by_case and finding.rule_id.startswith("CWE-"):
            by_case[case_id].append(finding)
    predictions: list[dict[str, Any]] = []
    for case_id in formal.CASE_IDS:
        path = f"testcode/{case_id}.java"
        candidates = sorted(
            by_case[case_id],
            key=lambda item: (-CONFIDENCE[item.confidence], item.line or 0, item.rule_id),
        )
        selected = candidates[0] if candidates else None
        if selected is None:
            predictions.append(
                {
                    "case_id": case_id,
                    "vulnerable": False,
                    "cwe": None,
                    "sink_line": None,
                    "confidence": 0.0,
                    "evidence_path": path,
                    "evidence_sha256": file_hashes[path],
                    "evidence_excerpt": "",
                    "rationale_summary": "The integrated Agent report contained no verified finding for this case.",
                }
            )
            continue
        predictions.append(
            {
                "case_id": case_id,
                "vulnerable": True,
                "cwe": int(selected.rule_id.removeprefix("CWE-")),
                "sink_line": selected.line,
                "confidence": CONFIDENCE[selected.confidence],
                "evidence_path": path,
                "evidence_sha256": file_hashes[path],
                "evidence_excerpt": str(selected.raw.get("evidence_excerpt", ""))[:400],
                "rationale_summary": selected.description[:500],
            }
        )
    return predictions


async def predict(benchmark: Path, report: Path, api_key: str, repetitions: int = formal.REPETITIONS) -> None:
    sealed_path = report / "raw" / "sealed-predictions.json"
    if sealed_path.exists():
        raise SystemExit("sealed integrated-agent predictions already exist")
    selected_cases, selected_support = formal._sources(benchmark)
    selection = formal._selection(selected_cases, selected_support)
    selection.update({"profile": "integrated-agent-40x3", "arm": "A-integrated-secmind-agent"})
    selection["selection_sha256"] = hashlib.sha256(
        json.dumps(selection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _json(report / "selection-manifest.json", selection)
    with tempfile.TemporaryDirectory(prefix="secmind-integrated-agent40-") as temporary:
        root = Path(temporary)
        settings = _settings(root, api_key)
        settings.prepare_directories()
        service, gateway = build_runtime(settings)
        runs: list[dict[str, Any]] = []
        started_at = formal._now()
        try:
            await service.startup()
            for repetition in range(1, repetitions + 1):
                attachment = f"integrated-agent40-r{repetition}"
                input_manifest, file_hashes = await asyncio.to_thread(
                    _stage,
                    benchmark,
                    settings.input_root / attachment,
                )
                run_id = service.submit(
                    TaskRequest(
                        client_request_id=f"agent40-{repetition}-{uuid4()}",
                        objective=(
                            "对锁定 Java 源码执行深度跨文件安全审计，使用所有已批准能力和 DeepSeek "
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
                async with asyncio.timeout(1800):
                    while True:
                        state = service.state(run_id)
                        queue_status, _lease, _queue_error = service.coordinator.job_snapshot(run_id)
                        if (
                            state.status in TERMINAL
                            and state.report is not None
                            and queue_status in {"completed", "cancelled", "recovery_required"}
                        ):
                            break
                        await asyncio.sleep(0.05)
                events = service.ledger.events(run_id)
                database_snapshot = service._replay_database_snapshot(run_id)
                prompt_artifacts = [
                    item.model_dump(
                        mode="json",
                        exclude={"system_prompt", "user_strategy_prefix"},
                    )
                    for item in service.orchestrator.prompt_service.artifacts(run_id)
                ]
                predictions = _predictions(state, file_hashes)
                run = {
                    "run_id": run_id,
                    "arm": "A-integrated-secmind-agent",
                    "repetition": repetition,
                    "status": state.status.value,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "input_manifest": input_manifest,
                    "provider_usage": state.budget.usage.model_dump(mode="json"),
                    "provider_attempts": database_snapshot["models"],
                    "prompt_artifacts": prompt_artifacts,
                    "model_calls_used": state.budget.model_calls_used,
                    "tool_calls_used": state.budget.tool_calls_used,
                    "plan": [step.model_dump(mode="json") for step in state.plan],
                    "selected_skill_ids": sorted(state.selected_skill_ids),
                    "step_skill_bindings": [
                        {
                            "step_id": step.step_id,
                            "signed_skill_ids": sorted(step.skill_ids),
                            "external_skill_card_ids": sorted(
                                step.context_requirements.get("external_skill_card_ids", [])
                            ),
                            "tool_candidates": sorted(step.tool_candidates),
                        }
                        for step in sorted(state.plan, key=lambda item: item.step_id)
                    ],
                    "outcome_contracts": [item.model_dump(mode="json") for item in state.outcome_contracts],
                    "decisions": [item.model_dump(mode="json") for item in state.decisions],
                    "claims": [item.model_dump(mode="json") for item in state.claims],
                    "verification_results": [item.model_dump(mode="json") for item in state.verification_results],
                    "contract_grades": state.contract_grades,
                    "finding_count": len(state.findings),
                    "findings": [item.model_dump(mode="json") for item in state.findings],
                    "audit_units": [item.model_dump(mode="json") for item in state.audit_units],
                    "audit_coverage": state.audit_coverage,
                    "reported_finding_count": len(state.report.findings) if state.report is not None else 0,
                    "evidence_count": len(state.evidence),
                    "evidence": [item.model_dump(mode="json") for item in state.evidence],
                    "evidence_links": [item.model_dump(mode="json") for item in state.evidence_links],
                    "ledger_event_count": len(events),
                    "ledger_valid": service.ledger.verify(run_id),
                    "limitations": state.report.limitations if state.report is not None else [state.last_error],
                    "last_error": state.last_error,
                    "predictions": predictions,
                }
                runs.append(run)
                _json(report / "raw" / f"repetition-{repetition}" / "agent-run.json", run)
                _json(
                    report / "raw" / f"repetition-{repetition}" / "predictions.json",
                    {"repetition": repetition, "predictions": predictions, "sealed_at": formal._now()},
                )
                print(
                    f"[integrated-agent-40x3] completed repetition {repetition}/{repetitions}",
                    file=sys.stderr,
                    flush=True,
                )
        finally:
            await service.shutdown()
            await gateway.close()

    usage = {
        "provider_requests": sum(len(item["provider_attempts"]) for item in runs),
        "successful_provider_requests": sum(
            attempt["status"] == "completed" for item in runs for attempt in item["provider_attempts"]
        ),
        "failed_provider_requests": sum(
            attempt["status"] != "completed" for item in runs for attempt in item["provider_attempts"]
        ),
        "input_tokens": sum(item["provider_usage"]["input_tokens"] for item in runs),
        "output_tokens": sum(item["provider_usage"]["output_tokens"] for item in runs),
        "total_latency_ms": sum(item["duration_ms"] for item in runs),
    }
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    usage["estimated_cost_upper_bound_usd"] = round(
        usage["input_tokens"] * 0.14 / 1_000_000 + usage["output_tokens"] * 0.28 / 1_000_000,
        8,
    )
    _json(
        sealed_path,
        {
            "schema_version": "1.0",
            "profile": "integrated-agent-40x3",
            "arm": "A-integrated-secmind-agent",
            "started_at": started_at,
            "sealed_at": formal._now(),
            "selection_sha256": selection["selection_sha256"],
            "model": {"id": formal.MODEL_ID, "reasoning_effort": "max"},
            "runs": runs,
            "usage": usage,
        },
    )
    print(json.dumps({"sealed": str(sealed_path), "usage": usage}, ensure_ascii=False))


def score(benchmark: Path, report: Path) -> None:
    sealed = json.loads((report / "raw" / "sealed-predictions.json").read_text(encoding="utf-8"))
    repetitions = sorted({int(item["repetition"]) for item in sealed.get("runs", [])})
    if repetitions != list(range(1, formal.REPETITIONS + 1)):
        raise SystemExit("formal scoring requires all three sealed repetitions")
    formal.score(benchmark, report)
    manifest_path = report / "experiment-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "product_version": "0.7.1",
            "profile": "integrated-agent-40x3",
            "arm": "A-integrated-secmind-agent",
            "evaluation_target": "SecMind v0.7 integrated Direct-first Agent runtime",
            "limitations": [
                "This is a descriptive integrated-runtime arm, not a receipt-matched A/B/C/D release proof.",
                "The fixed prompt path is authoritative because catalog strategy bodies are not yet approved.",
                "Restricted to four Java vulnerability categories and a public benchmark.",
            ],
        }
    )
    _json(manifest_path, manifest)
    targets = sorted(path for path in report.rglob("*") if path.is_file() and path.name != "hashes.sha256")
    (report / "hashes.sha256").write_text(
        "".join(f"{formal._sha(path)}  {path.relative_to(report).as_posix()}\n" for path in targets),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Integrated SecMind Agent 40x3 live evaluation")
    parser.add_argument("phase", choices=("predict", "score"))
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=formal.REPETITIONS)
    args = parser.parse_args()
    if args.phase == "predict":
        key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
        if not key:
            raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required")
        if args.repetitions < 1 or args.repetitions > formal.REPETITIONS:
            raise SystemExit(f"--repetitions must be between 1 and {formal.REPETITIONS}")
        asyncio.run(predict(args.benchmark_root.resolve(), args.report_dir.resolve(), key, args.repetitions))
    else:
        score(args.benchmark_root.resolve(), args.report_dir.resolve())


if __name__ == "__main__":
    main()
