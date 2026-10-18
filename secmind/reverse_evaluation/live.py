"""Run one sealed DeepSeek arm for the exploratory paired evaluation."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from secmind.config import Settings
from secmind.reverse_live_evaluation import run_live_arm


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    settings = Settings()
    if settings.model_mode != "live" or not settings.allow_live_models:
        raise RuntimeError("Live evaluation requires SECMIND_MODEL_MODE=live and SECMIND_ALLOW_LIVE_MODELS=true")
    if not settings.deepseek_api_key:
        raise RuntimeError("Live evaluation requires an independent SECMIND_DEEPSEEK_API_KEY")
    result = await run_live_arm(
        args.manifest,
        args.evidence,
        args.seal,
        args.output,
        settings=settings,
    )
    cases = result.get("cases")
    if not isinstance(cases, list) or len(cases) != 12:
        raise RuntimeError("canonical paired Live evaluation must contain all 12 cases")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="SecMind sealed DeepSeek reverse-analysis arm")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--seal", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = asyncio.run(_run(args))
    pricing = result.get("pricing")
    summary = {
        "arm": result.get("arm"),
        "case_count": len(result.get("cases", [])),
        "estimated_cny": pricing.get("estimated_cny") if isinstance(pricing, dict) else None,
        "output": str(args.output),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
