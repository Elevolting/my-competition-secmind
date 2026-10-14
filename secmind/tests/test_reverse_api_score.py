from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secmind.reverse_live_evaluation import estimate_deepseek_v4_flash_cny
from secmind.schemas import ModelUsage


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _identity(arm: str, case_id: str, repeat_id: int) -> dict[str, object]:
    return {
        "suite_id": "suite-api-12",
        "arm": arm,
        "case_id": case_id,
        "repeat_id": repeat_id,
        "sample_sha256": "a" * 64,
        "provider": "deepseek",
        "model": "deepseek-v4-flash",
    }


def _report(
    arm: str,
    case_id: str,
    repeat_id: int,
    *,
    status: str = "completed",
    behavior: str = "behavior_one",
    priority: str = "P2",
) -> dict[str, object]:
    identity = _identity(arm, case_id, repeat_id)
    return {
        "schema_version": "1.0",
        "artifact_type": "reverse_api_case_business_report",
        "task_identity": identity,
        "execution_status": status,
        "model_receipt_ref": "receipt.json",
        "source_semantics": {"evidence_boundary": "static evidence", "sources": ["fixture"]},
        "report": {
            "task_identity": identity,
            "execution_status": status,
            "executive_summary": "A human decision is required.",
            "reverse_analysis": f"PE format observed; claimed behavior is {behavior}.",
            "findings": [
                {
                    "title": behavior,
                    "severity": "low",
                    "confidence": "high",
                    "evidence_refs": [f"evidence-{case_id}"],
                    "business_impact": "fixture only",
                    "technical_explanation": f"The report identifies {behavior} from sealed evidence.",
                }
            ],
            "risk_assessment": {
                "overall_risk": "low",
                "impact_scope": "fixture",
                "exploitability": "unknown",
                "urgency": "normal",
            },
            "human_decision_recommendations": [
                {
                    "action": "Review",
                    "decision_role": "security owner",
                    "priority": priority,
                    "rationale": "Validate before action.",
                    "expected_outcome": "Documented decision.",
                }
            ],
            "next_steps": ["Validate evidence."],
            "limitations": ["Static evidence only."],
            "unknowns": ["Runtime behavior is unknown."],
            "evidence_refs": [f"evidence-{case_id}"],
            "model_receipt_ref": "receipt.json",
            "scoring_claims": {
                "status": status,
                "facts": {"format": "PE"},
                "behaviors": [behavior],
                "error": None,
            },
        },
    }


def _write_slot(
    run_root: Path,
    arm: str,
    case_id: str,
    repeat_id: int,
    *,
    status: str = "completed",
    behavior: str = "behavior_one",
    priority: str = "P2",
    gold_read: bool = False,
    tamper: str | None = None,
) -> Path:
    directory = run_root / arm / f"run-{repeat_id}" / case_id
    directory.mkdir(parents=True)
    identity = _identity(arm, case_id, repeat_id)
    report = _report(arm, case_id, repeat_id, status=status, behavior=behavior, priority=priority)
    request_public = {
        "task_identity": identity,
        "slot": {"arm": arm, "case_id": case_id, "repeat_id": repeat_id},
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "gold_read": gold_read,
        "sibling_runs_read": False,
        "safety_observation": {
            "task_identity": identity,
            "status": "verified",
            "safety": {
                "real_network_requests": 0,
                "host_pe_executions": 0,
                "target_writes": 0,
                "secret_leaks": 0,
            },
            "safety_receipts": {
                field: {"status": "verified", "count": 0, "evidence": ["fixture-receipt"]}
                for field in ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
            },
        },
    }
    request = request_public | {"public_request_sha256": _canonical_sha256(request_public)}
    per_attempt_usage = ModelUsage(provider_requests=1, input_tokens=10, output_tokens=5)
    aggregate_usage = ModelUsage(
        provider_requests=repeat_id,
        input_tokens=10 * repeat_id,
        output_tokens=5 * repeat_id,
    )
    logical_call_id = f"receipt-{arm}-{case_id}-{repeat_id}"
    receipt = {
        "task_identity": identity,
        "execution_status": status,
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "model_receipt_id": logical_call_id,
        "public_request_sha256": request["public_request_sha256"],
        "model_request_sha256": "b" * 64,
        "model_response_sha256": "c" * 64,
        "latency_ms": 100 + repeat_id,
        "retry_count": repeat_id - 1,
        "error_type": None if status != "unavailable" else "MODEL_GATEWAY_ERROR",
        "usage": {
            "provider_requests": repeat_id,
            "input_tokens": 10 * repeat_id,
            "output_tokens": 5 * repeat_id,
            "total_tokens": 15 * repeat_id,
            "cache_hit_input_tokens": 0,
            "cache_miss_input_tokens": 0,
            "cost_units": 0.0,
        },
        "pricing": estimate_deepseek_v4_flash_cny(
            aggregate_usage,
            priced_at=datetime(2026, 8, 24, tzinfo=UTC),
        ),
        "attempts": [
            {
                "ordinal": ordinal,
                "duration_ms": 101 // repeat_id if repeat_id == 1 else 51,
                "retryable": ordinal < repeat_id,
                "provider_request": True,
                "provider_request_id": f"provider-{arm}-{case_id}-{repeat_id}-{ordinal}",
                "logical_call_id": logical_call_id,
                "request_digest": "b" * 64,
                "response_digest": "c" * 64,
                "usage": per_attempt_usage.model_dump(mode="json"),
                "provider_reported_usage": per_attempt_usage.model_dump(mode="json"),
                "conservative_reserved_usage": ModelUsage().model_dump(mode="json"),
                "unknown_usage": False,
            }
            for ordinal in range(1, repeat_id + 1)
        ],
        "usage_provenance": {
            "provider_reported_usage": aggregate_usage.model_dump(mode="json"),
            "conservative_reserved_usage": ModelUsage().model_dump(mode="json"),
            "unknown_usage_attempts": 0,
        },
    }
    response = {
        "task_identity": identity,
        "execution_status": status,
        "model_response_sha256": "c" * 64,
        "report": report["report"],
    }
    payloads: dict[str, object | str] = {
        "request.json": request,
        "response.json": response,
        "receipt.json": receipt,
        "report.json": report,
        "report.md": "independent business report",
        "report.html": (
            "<html><head><meta http-equiv=\"Content-Security-Policy\" "
            "content=\"default-src 'none'\"></head><body>independent business report</body></html>"
        ),
    }
    for name, payload in payloads.items():
        text = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
        (directory / name).write_text(text, encoding="utf-8")
    seal = {
        "schema_version": "1.0",
        "suite_id": "suite-api-12",
        "arm": arm,
        "case_id": case_id,
        "repeat_id": repeat_id,
        "request_sha256": _sha256(directory / "request.json"),
        "response_sha256": _sha256(directory / "response.json"),
        "receipt_sha256": _sha256(directory / "receipt.json"),
        "report_json_sha256": _sha256(directory / "report.json"),
        "report_md_sha256": _sha256(directory / "report.md"),
        "report_html_sha256": _sha256(directory / "report.html"),
    }
    (directory / "seal.json").write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")
    if tamper is not None:
        target = directory / tamper
        target.write_text("tampered", encoding="utf-8")
    return directory


def _gold(path: Path) -> Path:
    cases = [
        {
            "id": f"case-{index:02d}",
            "obligations": [
                {"path": "facts.format", "equals": "PE", "category": "exact_fact"},
                {"path": "behaviors", "contains": "behavior_one"},
            ],
            "behaviors": ["behavior_one"],
        }
        for index in range(12)
    ]
    payload = {"schema_version": "1.0", "suite_id": "suite-api-12", "cases": cases}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _complete_tree(tmp_path: Path) -> tuple[Path, Path]:
    run_root = tmp_path / "api-runs"
    for arm in ("current", "optimized"):
        for repeat_id in (1, 2):
            for index in range(12):
                _write_slot(run_root, arm, f"case-{index:02d}", repeat_id)
    return run_root, _gold(tmp_path / "expected.json")


def _reseal(directory: Path) -> None:
    seal_path = directory / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    for name, field in {
        "request.json": "request_sha256",
        "response.json": "response_sha256",
        "receipt.json": "receipt_sha256",
        "report.json": "report_json_sha256",
        "report.md": "report_md_sha256",
        "report.html": "report_html_sha256",
    }.items():
        seal[field] = _sha256(directory / name)
    seal_path.write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")


def _rewrite_json(directory: Path, name: str, mutate: object) -> None:
    path = directory / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(payload)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _reseal(directory)


def _rebind_request_hash(payload: dict[str, object]) -> None:
    payload.pop("public_request_sha256", None)
    payload["public_request_sha256"] = _canonical_sha256(payload)


def test_score_rejects_incomplete_or_extra_or_duplicate_slots_before_opening_gold(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    missing = run_root / "current" / "run-1" / "case-00"
    for file in missing.iterdir():
        file.unlink()
    missing.rmdir()
    with pytest.raises(ValueError, match="exactly 48"):
        score_api_runs(run_root, tmp_path / "gold-must-not-be-read.json")

    complete_root, gold_path = _complete_tree(tmp_path / "extra")
    _write_slot(complete_root, "current", "case-extra", 1)
    with pytest.raises(ValueError, match="exactly 48"):
        score_api_runs(complete_root, gold_path)

    duplicate_root, duplicate_gold = _complete_tree(tmp_path / "duplicate")
    duplicate = duplicate_root / "current" / "run-1" / "case-00"
    copied = duplicate_root / "current" / "run-1" / "case-copy"
    copied.mkdir()
    for source in duplicate.iterdir():
        (copied / source.name).write_bytes(source.read_bytes())
    # A second copied seal is a duplicate logical report and therefore makes
    # the matrix 49 rather than the required 48 before gold can be opened.
    with pytest.raises(ValueError, match="exactly 48"):
        score_api_runs(duplicate_root, duplicate_gold)


@pytest.mark.parametrize("tamper", ["report.json", "receipt.json"])
def test_score_rejects_unsealed_or_tampered_report_before_opening_gold(tmp_path: Path, tamper: str) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    target = run_root / "current" / "run-1" / "case-00"
    if tamper == "report.json":
        (target / "seal.json").unlink()
    else:
        target = _write_slot(tmp_path / "other", "current", "case-00", 1, tamper=tamper)
        # Replace one valid directory without changing the matrix shape.
        original = run_root / "current" / "run-1" / "case-00"
        for file in original.iterdir():
            file.unlink()
        original.rmdir()
        target.rename(original)
    with pytest.raises(ValueError, match="seal|SHA256|unsealed"):
        score_api_runs(run_root, tmp_path / "gold-must-not-be-read.json")


def test_score_rejects_identity_cross_arm_and_gold_marker_before_gold_read(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, _gold_path = _complete_tree(tmp_path)
    request = run_root / "current" / "run-1" / "case-00" / "request.json"
    payload = json.loads(request.read_text(encoding="utf-8"))
    payload["gold_read"] = True
    request.write_text(json.dumps(payload), encoding="utf-8")
    seal_path = request.parent / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["request_sha256"] = _sha256(request)
    seal_path.write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="gold"):
        score_api_runs(run_root, tmp_path / "gold-must-not-be-read.json")

    run_root, _gold_path = _complete_tree(tmp_path / "cross-arm")
    report_path = run_root / "current" / "run-1" / "case-00" / "report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["task_identity"]["arm"] = "optimized"
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    seal_path = report_path.parent / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["report_json_sha256"] = _sha256(report_path)
    seal_path.write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="identity"):
        score_api_runs(run_root, tmp_path / "gold-must-not-be-read.json")


def test_score_reports_per_slot_arm_repeat_usage_and_api_mean_comparison(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    metrics, rows = score_api_runs(run_root, gold_path)

    assert len(rows) == 48
    assert metrics["slot_count"] == 48
    assert metrics["receipt_count"] == 48
    assert metrics["safety"]["real_network_requests"] == 0
    assert metrics["model_control_plane"]["provider_requests"] == 72
    assert metrics["arms"]["current"]["repeats"]["1"]["macro_obligation_score"] == 1.0
    assert metrics["comparison"]["optimized_minus_current"]["macro_obligation_score"] == 0.0
    assert all(row["behavior_f1"] == 1.0 for row in rows)
    assert all(row["report_path"].endswith("report.json") for row in rows)


@pytest.mark.parametrize(
    "mutation", ["missing_provenance", "missing_attempt_usage", "top_level_tokens", "selected_digest"]
)
def test_score_rejects_receipt_usage_or_identity_not_bound_to_attempt_ledger(
    tmp_path: Path, mutation: str
) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter(payload: dict[str, object]) -> None:
        if mutation == "missing_provenance":
            payload.pop("usage_provenance")
        elif mutation == "missing_attempt_usage":
            attempts = payload["attempts"]
            assert isinstance(attempts, list) and isinstance(attempts[0], dict)
            attempts[0].pop("provider_reported_usage")
        elif mutation == "top_level_tokens":
            usage = payload["usage"]
            assert isinstance(usage, dict)
            usage["input_tokens"] = 1000
            usage["total_tokens"] = 1005
            payload["pricing"] = estimate_deepseek_v4_flash_cny(
                ModelUsage(provider_requests=1, input_tokens=1000, output_tokens=5),
                priced_at=datetime(2026, 8, 24, tzinfo=UTC),
            )
        else:
            payload["model_response_sha256"] = "d" * 64

    _rewrite_json(directory, "receipt.json", alter)
    if mutation == "selected_digest":
        _rewrite_json(
            directory,
            "response.json",
            lambda payload: payload.__setitem__("model_response_sha256", "d" * 64),
        )
    with pytest.raises(ValueError, match="provenance|attempt|digest"):
        score_api_runs(run_root, gold_path)


def test_score_counts_paid_structured_output_failure_cost_from_provider_attempt(tmp_path: Path) -> None:
    """A local schema rejection is still a paid model failure, not a zero-cost gap."""

    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def make_failure(payload: dict[str, object]) -> None:
        payload["execution_status"] = "unavailable"
        report = payload["report"]
        assert isinstance(report, dict)
        report["execution_status"] = "unavailable"
        claims = report["scoring_claims"]
        assert isinstance(claims, dict)
        claims["status"] = "unavailable"
        claims["error"] = {"code": "STRUCTURED_OUTPUT_INVALID"}

    _rewrite_json(directory, "report.json", make_failure)
    _rewrite_json(directory, "response.json", lambda payload: make_failure(payload))

    def receipt_failure(payload: dict[str, object]) -> None:
        payload["execution_status"] = "unavailable"
        payload["error_type"] = "STRUCTURED_OUTPUT_INVALID"
        payload["usage"] = {
            "provider_requests": 1,
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "cache_hit_input_tokens": 0,
            "cache_miss_input_tokens": 0,
            "cost_units": 0.0,
        }
        payload["pricing"] = estimate_deepseek_v4_flash_cny(
            ModelUsage(provider_requests=1, input_tokens=100, output_tokens=20),
            priced_at=datetime(2026, 8, 24, tzinfo=UTC),
        )
        payload["latency_ms"] = 100
        payload["retry_count"] = 0
        payload["attempts"] = [
            {
                "ordinal": 1,
                "duration_ms": 100,
                "retryable": False,
                "provider_request": True,
                "provider_request_id": "provider-paid-failure",
                "logical_call_id": payload["model_receipt_id"],
                "request_digest": payload["model_request_sha256"],
                "response_digest": payload["model_response_sha256"],
                "usage": ModelUsage(provider_requests=1, input_tokens=100, output_tokens=20).model_dump(mode="json"),
                "provider_reported_usage": ModelUsage(
                    provider_requests=1, input_tokens=100, output_tokens=20
                ).model_dump(mode="json"),
                "conservative_reserved_usage": ModelUsage().model_dump(mode="json"),
                "unknown_usage": False,
            },
            {
                "ordinal": 2,
                "duration_ms": 0,
                "retryable": True,
                "provider_request": False,
                "provider_request_id": "provider-paid-failure",
                "logical_call_id": payload["model_receipt_id"],
                "request_digest": payload["model_request_sha256"],
                "response_digest": payload["model_response_sha256"],
                "usage": ModelUsage().model_dump(mode="json"),
                "provider_reported_usage": ModelUsage().model_dump(mode="json"),
                "conservative_reserved_usage": ModelUsage().model_dump(mode="json"),
                "unknown_usage": False,
            },
        ]
        payload["usage_provenance"] = {
            "provider_reported_usage": ModelUsage(
                provider_requests=1, input_tokens=100, output_tokens=20
            ).model_dump(mode="json"),
            "conservative_reserved_usage": ModelUsage().model_dump(mode="json"),
            "unknown_usage_attempts": 0,
        }

    _rewrite_json(directory, "receipt.json", receipt_failure)
    _rewrite_json(
        directory,
        "response.json",
        lambda payload: payload.__setitem__("error_type", "STRUCTURED_OUTPUT_INVALID"),
    )
    metrics, rows = score_api_runs(run_root, gold_path)
    row = next(
        row for row in rows if row["arm"] == "current" and row["repeat_id"] == 1 and row["case_id"] == "case-00"
    )
    assert row["model_failure"] is True
    assert row["provider_requests"] == 1
    assert row["total_tokens"] == 120
    assert row["estimated_cny"] > 0
    assert metrics["model_control_plane"]["estimated_cny"] > 0


def test_score_flags_conservative_usage_as_cost_incomplete_without_mixing_it_into_known_cost(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter(payload: dict[str, object]) -> None:
        attempts = payload["attempts"]
        assert isinstance(attempts, list) and isinstance(attempts[0], dict)
        conservative = ModelUsage(provider_requests=1, input_tokens=10, output_tokens=5).model_dump(mode="json")
        attempts[0]["provider_reported_usage"] = ModelUsage().model_dump(mode="json")
        attempts[0]["conservative_reserved_usage"] = conservative
        attempts[0]["usage"] = conservative
        attempts[0]["unknown_usage"] = True
        payload["usage_provenance"] = {
            "provider_reported_usage": ModelUsage().model_dump(mode="json"),
            "conservative_reserved_usage": conservative,
            "unknown_usage_attempts": 1,
        }

    _rewrite_json(directory, "receipt.json", alter)
    metrics, rows = score_api_runs(run_root, gold_path)
    row = next(
        row for row in rows if row["arm"] == "current" and row["repeat_id"] == 1 and row["case_id"] == "case-00"
    )
    assert row["unknown_usage_attempts"] == 1
    assert row["cost_complete"] is False
    assert row["known_estimated_cny"] == 0.0
    assert row["conservative_estimated_cny"] > 0
    assert metrics["model_control_plane"]["cost_complete"] is False
    assert metrics["model_control_plane"]["conservative_estimated_cny"] > 0


def test_score_reports_repeat_stability_and_population_summary(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    original = run_root / "current" / "run-2" / "case-00"
    for file in original.iterdir():
        file.unlink()
    original.rmdir()
    _write_slot(
        run_root,
        "current",
        "case-00",
        2,
        status="partial",
        behavior="behavior_two",
        priority="P1",
    )
    metrics, _rows = score_api_runs(run_root, gold_path)

    stability = metrics["arms"]["current"]["stability"]
    assert stability["status_agreement"] == pytest.approx(11 / 12)
    assert stability["behavior_jaccard"] == pytest.approx(11 / 12)
    assert stability["exact_fact_agreement"] == 1.0
    assert stability["recommendation_priority_agreement"] == pytest.approx(11 / 12)
    macro = metrics["arms"]["current"]["two_repeat_summary"]["macro_obligation_score"]
    assert macro["mean"] == pytest.approx(47 / 48)
    assert macro["minimum"] == pytest.approx(23 / 24)
    assert macro["maximum"] == 1.0
    assert macro["population_stddev"] == pytest.approx(1 / 48)


def test_score_uses_machine_claims_not_prose_or_gold_substrings(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter_report(payload: dict[str, object]) -> None:
        report = payload["report"]
        assert isinstance(report, dict)
        report["reverse_analysis"] = "This is explicitly not PE, despite the substring."
        claims = report["scoring_claims"]
        assert isinstance(claims, dict)
        claims["facts"] = {"format": "not-PE"}

    _rewrite_json(directory, "report.json", alter_report)
    _rewrite_json(
        directory,
        "response.json",
        lambda payload: alter_report({"report": payload["report"]}),
    )
    _reseal(directory)
    _metrics, rows = score_api_runs(run_root, gold_path)
    row = next(row for row in rows if row["arm"] == "current" and row["repeat_id"] == 1 and row["case_id"] == "case-00")
    assert row["exact_fact_accuracy"] == 0.0


def test_score_rejects_symlinked_artifact_before_gold_open(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"
    request = directory / "request.json"
    gold = tmp_path / "gold"
    gold.mkdir()
    copied = gold / "stolen-request.json"
    copied.write_bytes(request.read_bytes())
    request.unlink()
    try:
        os.symlink(copied, request)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    with pytest.raises(ValueError, match="symlink|gold|regular"):
        score_api_runs(run_root, gold_path)


def test_score_rejects_non_regular_artifact_before_any_gold_read(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform does not support FIFOs")
    run_root, gold_path = _complete_tree(tmp_path)
    request = run_root / "current" / "run-1" / "case-00" / "request.json"
    request.unlink()
    os.mkfifo(request)
    with pytest.raises(ValueError, match="regular"):
        score_api_runs(run_root, gold_path)


def test_score_rejects_mixed_suite_and_sample_before_gold_open(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    for label, key, value in (("suite", "suite_id", "different-suite"), ("sample", "sample_sha256", "b" * 64)):
        run_root, gold_path = _complete_tree(tmp_path / label)
        directory = run_root / "optimized" / "run-2" / "case-11"
        for name in ("request.json", "receipt.json", "response.json", "report.json"):
            def alter(
                payload: dict[str, object],
                *,
                name: str = name,
                key: str = key,
                value: str = value,
                directory: Path = directory,
            ) -> None:
                identity = payload.get("task_identity")
                assert isinstance(identity, dict)
                identity[key] = value
                if name == "request.json":
                    safety = payload.get("safety_observation")
                    if isinstance(safety, dict) and isinstance(safety.get("task_identity"), dict):
                        safety["task_identity"][key] = value
                    _rebind_request_hash(payload)
                if name == "receipt.json":
                    request_payload = json.loads((directory / "request.json").read_text(encoding="utf-8"))
                    payload["public_request_sha256"] = request_payload["public_request_sha256"]
                report = payload.get("report")
                if isinstance(report, dict):
                    nested = report.get("task_identity")
                    assert isinstance(nested, dict)
                    nested[key] = value

            _rewrite_json(directory, name, alter)
        seal_path = directory / "seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        if key == "suite_id":
            seal["suite_id"] = value
        seal_path.write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")
        with pytest.raises(ValueError, match="suite|sample"):
            score_api_runs(run_root, gold_path)


def test_score_fails_safety_gate_without_sealed_safety_observation(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"
    def remove_safety(payload: dict[str, object]) -> None:
        payload.pop("safety_observation")
        _rebind_request_hash(payload)

    _rewrite_json(directory, "request.json", remove_safety)
    _rewrite_json(
        directory,
        "receipt.json",
        lambda payload: payload.__setitem__(
            "public_request_sha256",
            json.loads((directory / "request.json").read_text(encoding="utf-8"))["public_request_sha256"],
        ),
    )
    metrics, _rows = score_api_runs(run_root, gold_path)
    assert metrics["safety_gate_passed"] is False
    assert metrics["safety"]["real_network_requests"] == -1


def test_score_rejects_nan_cost_and_inconsistent_receipt_accounting_before_gold(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter(payload: dict[str, object]) -> None:
        pricing = payload["pricing"]
        assert isinstance(pricing, dict)
        pricing["estimated_cny"] = float("nan")

    _rewrite_json(directory, "receipt.json", alter)
    with pytest.raises(ValueError, match="finite"):
        score_api_runs(run_root, gold_path)

    run_root, gold_path = _complete_tree(tmp_path / "accounting")
    directory = run_root / "current" / "run-1" / "case-00"

    def alter_usage(payload: dict[str, object]) -> None:
        usage = payload["usage"]
        assert isinstance(usage, dict)
        usage["provider_requests"] = 2
        usage["total_tokens"] = 99

    _rewrite_json(directory, "receipt.json", alter_usage)
    with pytest.raises(ValueError, match="total_tokens|provider_requests"):
        score_api_runs(run_root, gold_path)


def test_machine_claims_preserve_all_obligation_operators_and_repeat_claim_agreement(tmp_path: Path) -> None:
    from secmind.reverse_api_business import SecurityBusinessReport
    from secmind.reverse_api_score import _passes_obligation, _projection, score_api_runs

    report = SecurityBusinessReport.model_validate(
        _report("current", "case-00", 1, behavior="behavior_one")["report"]
        | {
            "scoring_claims": {
                "status": "completed",
                "facts": {"imports": ["strcmp", "fopen"], "section_count": 2, "created_files": []},
                "behaviors": ["behavior_one"],
                "error": None,
            }
        }
    )
    projection = _projection(report)
    for obligation in (
        {"path": "facts.imports", "contains": "strcmp"},
        {"path": "facts.imports", "contains": "fopen"},
        {"path": "behaviors", "not_contains": "dll_injection"},
        {"path": "facts.created_files", "length": 0},
        {"path": "unknowns", "min_length": 1},
        {"path": "facts.section_count", "min": 1},
        {"path": "status", "in": ["partial", "completed"]},
    ):
        assert _passes_obligation(projection, obligation)

    run_root, gold_path = _complete_tree(tmp_path)
    for repeat_id, wrong in ((1, "wrong-one"), (2, "wrong-two")):
        directory = run_root / "current" / f"run-{repeat_id}" / "case-00"

        def alter(payload: dict[str, object], *, wrong: str = wrong) -> None:
            report_payload = payload["report"]
            assert isinstance(report_payload, dict)
            claims = report_payload["scoring_claims"]
            assert isinstance(claims, dict)
            claims["facts"] = {"format": wrong}

        _rewrite_json(directory, "report.json", alter)
        _rewrite_json(directory, "response.json", lambda payload, alter=alter: alter({"report": payload["report"]}))
    metrics, _rows = score_api_runs(run_root, gold_path)
    assert metrics["arms"]["current"]["stability"]["exact_fact_agreement"] == pytest.approx(11 / 12)


def test_deepseek_pricing_receipt_is_pinned_and_arbitrary_finite_cost_is_rejected(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs
    from secmind.reverse_live_evaluation import DEEPSEEK_PRICING_SOURCE

    assert DEEPSEEK_PRICING_SOURCE == "https://api-docs.deepseek.com/quick_start/pricing-details-cny/"
    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter(payload: dict[str, object]) -> None:
        pricing = payload["pricing"]
        assert isinstance(pricing, dict)
        pricing["estimated_cny"] = 999999.0

    _rewrite_json(directory, "receipt.json", alter)
    with pytest.raises(ValueError, match="pricing|CNY"):
        score_api_runs(run_root, gold_path)


def test_completed_slot_requires_a_real_deepseek_attempt_and_request(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def erase_attempts(payload: dict[str, object]) -> None:
        payload["attempts"] = []
        payload["latency_ms"] = 0
        payload["retry_count"] = 0
        usage = payload["usage"]
        assert isinstance(usage, dict)
        usage["provider_requests"] = 0

    _rewrite_json(directory, "receipt.json", erase_attempts)
    with pytest.raises(ValueError, match="DeepSeek receipt|provider_requests|aggregate provider attempt"):
        score_api_runs(run_root, gold_path)


def test_score_binds_request_endpoint_response_error_and_success_claim_semantics(tmp_path: Path) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    directory = run_root / "current" / "run-1" / "case-00"

    def alter_url(payload: dict[str, object]) -> None:
        payload["base_url"] = "https://attacker.invalid"
        _rebind_request_hash(payload)

    _rewrite_json(directory, "request.json", alter_url)
    _rewrite_json(
        directory,
        "receipt.json",
        lambda payload: payload.__setitem__(
            "public_request_sha256",
            json.loads((directory / "request.json").read_text(encoding="utf-8"))["public_request_sha256"],
        ),
    )
    with pytest.raises(ValueError, match="provider identity"):
        score_api_runs(run_root, gold_path)

    run_root, gold_path = _complete_tree(tmp_path / "errors")
    directory = run_root / "current" / "run-1" / "case-00"
    _rewrite_json(directory, "response.json", lambda payload: payload.__setitem__("error_type", "TIMEOUT"))
    with pytest.raises(ValueError, match="error types"):
        score_api_runs(run_root, gold_path)

    run_root, gold_path = _complete_tree(tmp_path / "claim")
    directory = run_root / "current" / "run-1" / "case-00"

    def provider_claim(payload: dict[str, object]) -> None:
        report = payload["report"]
        assert isinstance(report, dict)
        claims = report["scoring_claims"]
        assert isinstance(claims, dict)
        claims["error"] = {"code": "MODEL_GATEWAY_ERROR"}

    _rewrite_json(directory, "report.json", provider_claim)
    _rewrite_json(directory, "response.json", lambda payload: provider_claim({"report": payload["report"]}))
    with pytest.raises(ValueError, match="provider failure"):
        score_api_runs(run_root, gold_path)


@pytest.mark.parametrize("case_status, code", [("partial", "MALFORMED_PE"), ("partial", "DYNAMIC_UNAVAILABLE")])
def test_score_passes_real_gold_domain_error_claims_end_to_end(
    tmp_path: Path,
    case_status: str,
    code: str,
) -> None:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    cases = gold["cases"]
    assert isinstance(cases, list)
    cases[0] = {
        "id": "case-00",
        "obligations": [
            {"path": "status", "equals": case_status},
            {"path": "facts.format", "equals": "PE", "category": "exact_fact"},
            {"path": "error.code", "equals": code},
        ],
        "behaviors": [],
    }
    gold_path.write_text(json.dumps(gold), encoding="utf-8")
    for arm in ("current", "optimized"):
        for repeat_id in (1, 2):
            directory = run_root / arm / f"run-{repeat_id}" / "case-00"

            def alter_report(payload: dict[str, object], *, code: str = code) -> None:
                payload["execution_status"] = case_status
                report = payload["report"]
                assert isinstance(report, dict)
                report["execution_status"] = case_status
                claims = report["scoring_claims"]
                assert isinstance(claims, dict)
                claims["status"] = case_status
                claims["error"] = {"code": code}

            _rewrite_json(directory, "report.json", alter_report)
            _rewrite_json(
                directory,
                "response.json",
                lambda payload, alter_report=alter_report: alter_report(payload),
            )
            _rewrite_json(
                directory,
                "receipt.json",
                lambda payload: payload.__setitem__("execution_status", case_status),
            )
    _metrics, rows = score_api_runs(run_root, gold_path)
    for row in rows:
        if row["case_id"] == "case-00":
            assert row["obligation_score"] == 1.0
