"""Run a bounded live A/B of the legacy and cache-stable canonical prompts.

The script never persists provider response text or credentials. It records
only token telemetry, latency, status, and coarse finding identifiers.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any

from secmind.canonical_primary import (
    CanonicalAnalysisContract,
    CanonicalInputView,
    SourceCodePrimaryAnswer,
    canonical_system_prompt,
    canonical_user_prompt,
    canonical_user_prompt_v2,
)
from secmind.config import Settings
from secmind.llm import QwenGateway

MODEL_ID = "deepseek-v4-flash"
BASE_URL = "https://api.deepseek.com"


def _fixture_source(nonce: str = "default") -> str:
    helpers = "\n".join(
        f"def normalize_{index}(value: str) -> str:\n    return value.strip().replace('alias_{index}', 'value')\n"
        for index in range(100)
    )
    return (
        f"# cache_experiment_nonce={nonce}\n"
        "import hashlib\nimport subprocess\n\n"
        "SERVICE_PASSWORD = 'competition-fixture-password'\n\n"  # noqa: S105 - inert audit fixture
        "def run_user_command(command: str) -> str:\n"
        "    return subprocess.check_output(command, shell=True, text=True)\n\n"
        "def legacy_password_digest(password: str) -> str:\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n\n" + helpers
    )


def _contracts(source: str) -> tuple[list[CanonicalAnalysisContract], list[CanonicalInputView]]:
    digest = hashlib.sha256(source.encode()).hexdigest()
    view = CanonicalInputView(
        path="src/application.py",
        sha256=digest,
        size_bytes=len(source.encode()),
        media_type="text/x-python",
        representation="text",
        content=source,
    )
    objectives = (
        "Audit this Python service for reachable security vulnerabilities.",
        "Review this Python service and explain each security root cause and impact.",
        "Find actionable CWEs in this Python service and provide concrete remediations.",
    )
    contracts = [
        CanonicalAnalysisContract(
            task_id=f"CACHE-AB-{index}",
            objective=objective,
            scenario="code_audit",
            analysis_profile="source_code_security",
            target_scope=["src/application.py"],
            constraints=["read-only static analysis"],
            expected_outputs=["root_cause", "impact", "remediation"],
            autonomy_policy="automatic",
            inputs=[
                {
                    "path": view.path,
                    "sha256": view.sha256,
                    "size_bytes": view.size_bytes,
                    "media_type": view.media_type,
                }
            ],
            viewed_paths=[view.path],
            omitted_paths=[],
            context_sha256=hashlib.sha256(f"{digest}:{index}".encode()).hexdigest(),
        )
        for index, objective in enumerate(objectives, start=1)
    ]
    return contracts, [view]


def _normalized_cwe(value: str | int | None) -> str:
    raw = str(value or "UNKNOWN").upper().removeprefix("CWE-")
    return f"CWE-{raw}"


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.allow_live:
        raise SystemExit("live evaluation requires --allow-live")
    api_key = os.environ.get("SECMIND_DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("SECMIND_DEEPSEEK_API_KEY is required")
    source = _fixture_source(args.nonce)
    contracts, views = _contracts(source)
    settings = Settings(
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
        model_reasoning_effort="high",
        model_thinking_enabled=True,
        model_max_output_tokens=8192,
        model_max_attempts=1,
        model_structured_repair_attempts=1,
        model_timeout_seconds=120,
    )
    gateway = QwenGateway(settings)
    renderers: dict[str, Callable[[CanonicalAnalysisContract, list[CanonicalInputView]], str]] = {
        "legacy_task_first_v2": canonical_user_prompt_v2,
        "cache_stable_evidence_first_v3": canonical_user_prompt,
    }
    arm_order = list(renderers)
    if args.stable_first:
        arm_order.reverse()
    rows: dict[str, list[dict[str, Any]]] = {name: [] for name in renderers}
    system_prompt = canonical_system_prompt("source_code_security")
    try:
        for index, contract in enumerate(contracts, start=1):
            for arm in arm_order:
                renderer = renderers[arm]
                started = monotonic()
                answer, meta = await gateway.structured(
                    role="planner",
                    system_prompt=system_prompt,
                    user_prompt=renderer(contract, views),
                    output_model=SourceCodePrimaryAnswer,
                    prompt_version=arm,
                )
                rows[arm].append(
                    {
                        "request": index,
                        "provider_requests": meta.usage.provider_requests,
                        "prompt_tokens": meta.usage.input_tokens,
                        "cache_hit_tokens": meta.usage.cache_hit_input_tokens,
                        "cache_miss_tokens": meta.usage.cache_miss_input_tokens,
                        "output_tokens": meta.usage.output_tokens,
                        "latency_ms": round((monotonic() - started) * 1000),
                        "status": answer.status,
                        "finding_count": len(answer.findings),
                        "cwes": sorted({_normalized_cwe(item.cwe) for item in answer.findings}),
                    }
                )
                await asyncio.sleep(args.cache_settle_seconds)
    finally:
        await gateway.close()

    aggregates: dict[str, dict[str, Any]] = {}
    for arm, arm_rows in rows.items():
        prompt_tokens = sum(row["prompt_tokens"] for row in arm_rows)
        hit_tokens = sum(row["cache_hit_tokens"] for row in arm_rows)
        miss_tokens = sum(row["cache_miss_tokens"] for row in arm_rows)
        aggregates[arm] = {
            "provider_requests": sum(row["provider_requests"] for row in arm_rows),
            "prompt_tokens": prompt_tokens,
            "cache_hit_tokens": hit_tokens,
            "cache_miss_tokens": miss_tokens,
            "cache_hit_rate": hit_tokens / prompt_tokens if prompt_tokens else 0,
            "latency_ms": sum(row["latency_ms"] for row in arm_rows),
            "finding_count": sum(row["finding_count"] for row in arm_rows),
        }
    legacy = aggregates["legacy_task_first_v2"]
    optimized = aggregates["cache_stable_evidence_first_v3"]
    optimized_rows = rows["cache_stable_evidence_first_v3"]

    def meets_task_gold(row: dict[str, Any]) -> bool:
        cwes = set(row["cwes"])
        has_weak_hash = bool(cwes.intersection({"CWE-327", "CWE-328", "CWE-916"}))
        # The first objective is intentionally limited to reachable flaws; the
        # fixture credential constant is unused and must not be required as a
        # positive. The broader second and third objectives require it.
        expected = {"CWE-78"} <= cwes and has_weak_hash
        if row["request"] > 1:
            expected = expected and "CWE-798" in cwes
        return bool(expected)

    return {
        "schema_version": "1.0",
        "experiment": "deepseek-canonical-prefix-cache-ab",
        "recorded_at": datetime.now(UTC).isoformat(),
        "model": MODEL_ID,
        "base_url_host": "api.deepseek.com",
        "reasoning_effort": "high",
        "thinking_enabled": True,
        "max_output_tokens": 8192,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "source_bytes": len(source.encode()),
        "raw_response_saved": False,
        "schedule": f"{' then '.join(arm_order)}, interleaved per task",
        "rows": rows,
        "aggregate": aggregates,
        "comparison": {
            "cache_hit_rate_delta": optimized["cache_hit_rate"] - legacy["cache_hit_rate"],
            "cache_miss_token_reduction": legacy["cache_miss_tokens"] - optimized["cache_miss_tokens"],
            "finding_count_delta": optimized["finding_count"] - legacy["finding_count"],
            "cache_gate_passed": optimized["cache_hit_rate"] > legacy["cache_hit_rate"],
            "quality_smoke_passed": (
                all(row["status"] in {"completed", "partial"} for row in optimized_rows)
                and all(meets_task_gold(row) for row in optimized_rows)
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-live", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-settle-seconds", type=float, default=3.0)
    parser.add_argument("--nonce", default="default", help="Non-secret fixture nonce used to isolate provider caches")
    parser.add_argument("--stable-first", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(_run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "comparison": result["comparison"]}, ensure_ascii=False))
    if not result["comparison"]["cache_gate_passed"] or not result["comparison"]["quality_smoke_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
