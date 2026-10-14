from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import pytest

from secmind.config import Settings
from secmind.reverse_evaluation import seal_predictions
from secmind.reverse_live_evaluation import (
    estimate_deepseek_v4_flash_cny,
    preflight_live_pair,
    run_live_arm,
)
from secmind.schemas import ModelUsage


def _deepseek_settings() -> Settings:
    return Settings(
        _env_file=None,
        demo_mode=False,
        model_mode="mock",
        model_base_url_provider="deepseek",
        qwen_base_url="https://api.deepseek.com",
        trusted_model_base_urls="https://api.deepseek.com",
        planner_model="deepseek-v4-flash",
        worker_model="deepseek-v4-flash",
        fallback_model="deepseek-v4-flash",
        deepseek_api_key="test-deepseek-key",
        qwen_api_key="qwen-must-not-be-used",
        model_thinking_enabled=True,
        model_reasoning_effort="high",
        model_structured_output_mode="json_object",
    )


def test_cost_estimate_uses_current_peak_and_off_peak_cny_snapshot() -> None:
    usage = ModelUsage(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        cache_hit_input_tokens=200_000,
        cache_miss_input_tokens=800_000,
    )

    off_peak = estimate_deepseek_v4_flash_cny(
        usage,
        priced_at=datetime(2026, 8, 24, 3, tzinfo=ZoneInfo("Asia/Shanghai")),
    )
    peak = estimate_deepseek_v4_flash_cny(
        usage,
        priced_at=datetime(2026, 8, 24, 10, tzinfo=ZoneInfo("Asia/Shanghai")),
    )

    assert off_peak["pricing_band"] == "off_peak"
    assert off_peak["estimated_cny"] == pytest.approx(0.2 * 0.05 + 0.8 * 1.5 + 4.5)
    assert peak["pricing_band"] == "peak"
    assert peak["estimated_cny"] == pytest.approx(0.2 * 0.10 + 0.8 * 3.0 + 9.0)


@pytest.mark.asyncio
async def test_live_arm_uses_public_evidence_and_saves_receipts_without_gold(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    evidence = tmp_path / "predictions.json"
    evidence_seal = tmp_path / "predictions.seal.json"
    output = tmp_path / "live.json"
    manifest.write_text(
        json.dumps(
            {
                "suite_id": "suite",
                "cases": [{"id": "case-1", "prompt": "分析安全样本", "kind": "pe_static"}],
            }
        ),
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps(
            {
                "suite_id": "suite",
                "arm": "optimized",
                "cases": [
                    {
                        "id": "case-1",
                        "status": "completed",
                        "facts": {"format": "PE"},
                        "behaviors": ["file_io"],
                        "evidence_refs": ["e-1"],
                        "limitations": [],
                        "unknowns": [],
                        "error": None,
                    }
                ],
                "safety": {
                    "real_network_requests": 0,
                    "host_pe_executions": 0,
                    "target_writes": 0,
                    "secret_leaks": 0,
                },
                "safety_receipts": {
                    field: {"status": "verified", "count": 0, "evidence": [f"test:{field}"]}
                    for field in ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
                },
            }
        ),
        encoding="utf-8",
    )
    seal_predictions(evidence, evidence_seal)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "status": "completed",
                                    "facts": {"format": "PE"},
                                    "behaviors": ["file_io"],
                                    "evidence_refs": ["e-1"],
                                    "limitations": [],
                                    "unknowns": [],
                                    "error": None,
                                }
                            )
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "prompt_cache_hit_tokens": 20,
                    "prompt_cache_miss_tokens": 80,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await run_live_arm(
            manifest,
            evidence,
            evidence_seal,
            output,
            settings=_deepseek_settings(),
            client=http,
            priced_at=datetime(2026, 8, 24, 3, tzinfo=ZoneInfo("Asia/Shanghai")),
        )

    assert result["cases"][0]["facts"] == {"format": "PE"}
    assert result["cases"][0]["model_receipt"]["input_tokens"] == 100
    assert result["aggregate_receipt"]["provider_requests"] == 1
    assert result["pricing"]["pricing_band"] == "off_peak"
    assert result["gold_read"] is False
    assert result["safety"]["secret_leaks"] == 0
    assert requests[0].url.host == "api.deepseek.com"
    assert requests[0].headers["Authorization"] == "Bearer test-deepseek-key"
    assert b"qwen-must-not-be-used" not in requests[0].content
    assert output.is_file()


def test_live_pair_preflight_verifies_both_seals_without_exposing_credentials(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "suite_id": "suite",
                "cases": [{"id": f"case-{index}", "prompt": "safe"} for index in range(12)],
            }
        ),
        encoding="utf-8",
    )
    arms: dict[str, tuple[Path, Path]] = {}
    for arm in ("current", "optimized"):
        evidence = tmp_path / f"{arm}.json"
        seal = tmp_path / f"{arm}.seal.json"
        evidence.write_text(
            json.dumps(
                {
                    "suite_id": "suite",
                    "arm": arm,
                    "cases": [{"id": f"case-{index}"} for index in range(12)],
                }
            ),
            encoding="utf-8",
        )
        seal_predictions(evidence, seal)
        arms[arm] = (evidence, seal)

    settings = _deepseek_settings().model_copy(
        update={"model_mode": "live", "allow_live_models": True, "deepseek_api_key": ""}
    )
    result = preflight_live_pair(manifest, arms, settings=settings)

    assert result["ready"] is False
    assert result["reason"] == "missing_deepseek_credential"
    assert result["network_requests_made"] == 0
    assert result["gold_read"] is False
    assert result["case_count"] == 12
    assert set(result["arms"]) == {"current", "optimized"}
    assert all(item["seal_verified"] for item in result["arms"].values())
    assert "test-deepseek-key" not in json.dumps(result)
    assert "deepseek_api_key" not in json.dumps(result)
