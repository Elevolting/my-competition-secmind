"""DeepSeek evidence-fusion runner for paired reverse-analysis evaluation."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from pydantic import BaseModel, ConfigDict, Field

from secmind.config import Settings
from secmind.llm import QwenGateway
from secmind.reverse_evaluation import verify_prediction_seal
from secmind.schemas import ModelUsage

DEEPSEEK_PRICING_SOURCE = "https://api-docs.deepseek.com/quick_start/pricing-details-cny/"
DEEPSEEK_PRICING_SNAPSHOT: dict[str, Any] = {
    "schema_version": "1.0",
    "currency": "CNY",
    "unit_tokens": 1_000_000,
    "model": "deepseek-v4-flash",
    "peak_beijing_hours": ["09:00-12:00", "14:00-18:00"],
    "off_peak": {"cache_hit_input": 0.05, "cache_miss_input": 1.5, "output": 4.5},
    "peak": {"cache_hit_input": 0.10, "cache_miss_input": 3.0, "output": 9.0},
    "source": DEEPSEEK_PRICING_SOURCE,
    "retrieved_at": "2026-08-24",
}


class LiveReverseAnswer(BaseModel):
    """Structured answer returned by the model; hidden reasoning is never requested."""

    model_config = ConfigDict(extra="forbid")

    status: str
    facts: dict[str, Any] = Field(default_factory=dict)
    behaviors: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    error: dict[str, Any] | None = None


def estimate_deepseek_v4_flash_cny(
    usage: ModelUsage,
    *,
    priced_at: datetime,
) -> dict[str, Any]:
    """Estimate CNY cost from a date-bound official pricing snapshot."""

    aware = priced_at.replace(tzinfo=UTC) if priced_at.tzinfo is None else priced_at
    beijing = aware.astimezone(ZoneInfo("Asia/Shanghai"))
    peak = 9 <= beijing.hour < 12 or 14 <= beijing.hour < 18
    band = "peak" if peak else "off_peak"
    rates = DEEPSEEK_PRICING_SNAPSHOT[band]
    cache_hit = usage.cache_hit_input_tokens
    cache_miss = usage.cache_miss_input_tokens
    cache_accounting = "provider_reported"
    if cache_hit + cache_miss == 0:
        # Older provider receipts can omit cache split.  Price conservatively
        # as cache misses and make that fallback explicit in the sealed record.
        cache_miss = usage.input_tokens
        cache_accounting = "conservative_cache_miss_fallback"
    estimated = (
        cache_hit * rates["cache_hit_input"]
        + cache_miss * rates["cache_miss_input"]
        + usage.output_tokens * rates["output"]
    ) / int(DEEPSEEK_PRICING_SNAPSHOT["unit_tokens"])
    return {
        "pricing_band": band,
        "priced_at": beijing.isoformat(),
        "estimated_cny": round(estimated, 8),
        "snapshot": dict(DEEPSEEK_PRICING_SNAPSHOT),
        "usage_components": {
            "cache_hit_input_tokens": cache_hit,
            "cache_miss_input_tokens": cache_miss,
            "output_tokens": usage.output_tokens,
            "cache_accounting": cache_accounting,
        },
        "formula": "(cache_hit_input*rate + cache_miss_input*rate + output*rate) / 1000000",
    }


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _ordered_case_ids(payload: dict[str, Any], *, label: str) -> list[str]:
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"{label} cases must be a list")
    values = [str(item.get("id", "")) for item in cases if isinstance(item, dict)]
    if len(values) != len(cases) or not all(values) or len(values) != len(set(values)):
        raise ValueError(f"{label} case IDs must be present and unique")
    return values


def validate_deepseek_identity(settings: Settings) -> None:
    """Fail closed unless the reviewed DeepSeek evaluation identity is configured."""

    if settings.qwen_base_url.rstrip("/") != "https://api.deepseek.com":
        raise ValueError("paired Live requires the official https://api.deepseek.com base URL")
    if settings.model_base_url_provider != "deepseek":
        raise ValueError("paired Live requires model_base_url_provider=deepseek")
    if {settings.planner_model, settings.worker_model, settings.fallback_model} != {"deepseek-v4-flash"}:
        raise ValueError("paired Live requires deepseek-v4-flash for planner, worker, and fallback")
    if not settings.model_thinking_enabled or settings.model_reasoning_effort != "high":
        raise ValueError("paired Live requires thinking enabled and reasoning effort high")
    if settings.model_structured_output_mode != "json_object":
        raise ValueError("paired Live requires JSON-object structured output")


def preflight_live_pair(
    manifest_path: Path,
    arms: dict[str, tuple[Path, Path]],
    *,
    settings: Settings,
) -> dict[str, Any]:
    """Validate a canonical paired Live run without reading gold or making network requests."""

    validate_deepseek_identity(settings)
    if set(arms) != {"current", "optimized"}:
        raise ValueError("paired Live preflight requires current and optimized arms")
    manifest = _load_object(manifest_path)
    manifest_case_ids = _ordered_case_ids(manifest, label="manifest")
    if len(manifest_case_ids) != 12:
        raise ValueError("canonical paired Live evaluation requires exactly 12 cases")
    arm_receipts: dict[str, dict[str, Any]] = {}
    for arm in ("current", "optimized"):
        evidence_path, seal_path = arms[arm]
        seal = verify_prediction_seal(evidence_path, seal_path)
        evidence = _load_object(evidence_path)
        if evidence.get("suite_id") != manifest.get("suite_id"):
            raise ValueError(f"{arm} evidence suite_id differs from the manifest")
        if evidence.get("arm") != arm:
            raise ValueError(f"{arm} evidence arm identity differs from its pair label")
        if _ordered_case_ids(evidence, label=f"{arm} evidence") != manifest_case_ids:
            raise ValueError(f"{arm} evidence case IDs differ from the manifest")
        arm_receipts[arm] = {
            "seal_verified": True,
            "case_count": len(manifest_case_ids),
            "prediction_sha256": seal["prediction_sha256"],
        }

    live_mode_ready = settings.model_mode == "live" and settings.allow_live_models
    credential_present = bool(settings.deepseek_api_key)
    ready = live_mode_ready and credential_present
    if not live_mode_ready:
        reason = "live_model_mode_disabled"
    elif not credential_present:
        reason = "missing_deepseek_credential"
    else:
        reason = "ready"
    return {
        "schema_version": "1.0",
        "ready": ready,
        "reason": reason,
        "gold_read": False,
        "network_requests_made": 0,
        "case_count": len(manifest_case_ids),
        "configuration": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-flash",
            "thinking_enabled": settings.model_thinking_enabled,
            "reasoning_effort": settings.model_reasoning_effort,
            "structured_output": settings.model_structured_output_mode,
            "credential_present": credential_present,
        },
        "arms": arm_receipts,
    }


def _usage_dict(usage: ModelUsage) -> dict[str, Any]:
    return usage.model_dump(mode="json") | {"total_tokens": usage.total_tokens}


async def run_live_arm(
    manifest_path: Path,
    evidence_path: Path,
    evidence_seal_path: Path,
    output_path: Path,
    *,
    settings: Settings,
    client: httpx.AsyncClient | None = None,
    priced_at: datetime | None = None,
) -> dict[str, Any]:
    """Run one arm from public prompts and pre-gold sealed evidence only."""

    validate_deepseek_identity(settings)
    seal = verify_prediction_seal(evidence_path, evidence_seal_path)
    manifest = _load_object(manifest_path)
    evidence = _load_object(evidence_path)
    if manifest.get("suite_id") != evidence.get("suite_id"):
        raise ValueError("manifest and evidence suite_id differ")
    if _ordered_case_ids(manifest, label="manifest") != _ordered_case_ids(evidence, label="evidence"):
        raise ValueError("manifest and sealed evidence case IDs differ")
    evidence_by_id = {str(item["id"]): item for item in evidence.get("cases", [])}
    gateway = QwenGateway(settings, client)
    case_outputs: list[dict[str, Any]] = []
    total_usage = ModelUsage()
    try:
        for case in manifest.get("cases", []):
            case_id = str(case["id"])
            source = evidence_by_id.get(case_id)
            if source is None:
                case_outputs.append(
                    {
                        "id": case_id,
                        "status": "unavailable",
                        "facts": {},
                        "behaviors": [],
                        "evidence_refs": [],
                        "limitations": ["sealed evidence was missing for this case"],
                        "unknowns": [],
                        "error": {"code": "LIVE_EVIDENCE_MISSING"},
                        "model_receipt": None,
                    }
                )
                continue
            prompt_payload = {
                "case_id": case_id,
                "question": case.get("prompt"),
                "evidence": source,
                "instruction": "只根据 evidence 形成结构化答案；静态存在、仿真观测与未知项必须明确区分。",
            }
            try:
                answer, meta = await gateway.structured(
                    role="planner",
                    call_purpose="auxiliary",
                    system_prompt=(
                        "你是安全逆向证据融合器。不要输出隐藏思维链。只返回符合 schema 的 JSON；"
                        "不得把导入存在升级为运行时调用，也不得覆盖工具限制。"
                    ),
                    user_prompt=json.dumps(prompt_payload, ensure_ascii=False, sort_keys=True),
                    output_model=LiveReverseAnswer,
                    prompt_version="reverse-live-v1",
                    run_id=f"reverse-live-{evidence.get('arm', 'unknown')}-{case_id}",
                )
                answer_payload = answer.model_dump(mode="json")
                allowed_evidence = set(map(str, source.get("evidence_refs", [])))
                invalid_refs = [item for item in answer_payload["evidence_refs"] if item not in allowed_evidence]
                if invalid_refs:
                    answer_payload["evidence_refs"] = [
                        item for item in answer_payload["evidence_refs"] if item in allowed_evidence
                    ]
                    answer_payload["status"] = "partial"
                    answer_payload["limitations"].append("model returned evidence references outside the sealed packet")
                    answer_payload["error"] = {"code": "LIVE_EVIDENCE_REF_INVALID"}
                total_usage = ModelUsage(
                    provider_requests=total_usage.provider_requests + meta.usage.provider_requests,
                    input_tokens=total_usage.input_tokens + meta.usage.input_tokens,
                    output_tokens=total_usage.output_tokens + meta.usage.output_tokens,
                    cache_hit_input_tokens=(total_usage.cache_hit_input_tokens + meta.usage.cache_hit_input_tokens),
                    cache_miss_input_tokens=(total_usage.cache_miss_input_tokens + meta.usage.cache_miss_input_tokens),
                    cost_units=total_usage.cost_units + meta.usage.cost_units,
                )
                receipt = {
                    "model_receipt_id": meta.logical_call_id or meta.response_sha256,
                    "model_id": meta.model_id,
                    "provider": meta.provider,
                    "request_sha256": meta.request_sha256,
                    "response_sha256": meta.response_sha256,
                    "latency_ms": meta.duration_ms,
                    "used_fallback": meta.used_fallback,
                    **_usage_dict(meta.usage),
                    "retry_count": max(0, len(meta.attempts) - 1),
                    "attempts": [item.model_dump(mode="json") for item in meta.attempts],
                }
                case_outputs.append({"id": case_id, **answer_payload, "model_receipt": receipt})
            except Exception as exc:  # noqa: BLE001 - retain a complete paired case ledger
                case_outputs.append(
                    {
                        "id": case_id,
                        "status": "unavailable",
                        "facts": {},
                        "behaviors": [],
                        "evidence_refs": [],
                        "limitations": ["DeepSeek structured call did not complete"],
                        "unknowns": [],
                        "error": {"code": "LIVE_MODEL_CALL_FAILED", "type": type(exc).__name__},
                        "model_receipt": None,
                    }
                )
    finally:
        await gateway.close()

    price_time = priced_at or datetime.now(UTC)
    result = {
        "schema_version": "1.0",
        "suite_id": manifest.get("suite_id"),
        "arm": evidence.get("arm"),
        "exploratory": True,
        "gold_read": False,
        "evidence_sha256": seal["prediction_sha256"],
        "run_identity": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-flash",
            "thinking_enabled": True,
            "reasoning_effort": "high",
            "structured_output": "json_object",
        },
        "cases": case_outputs,
        "aggregate_receipt": _usage_dict(total_usage),
        "pricing": estimate_deepseek_v4_flash_cny(total_usage, priced_at=price_time),
        "safety": dict(evidence.get("safety", {})),
        "safety_receipts": dict(evidence.get("safety_receipts", {})),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(
        output_path.write_text,
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result
