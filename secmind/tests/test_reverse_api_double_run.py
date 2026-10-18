from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import queue
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from secmind.config import Settings
from secmind.reverse_evaluation import seal_predictions


def _settings() -> Settings:
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


def _inputs(tmp_path: Path) -> tuple[Path, dict[str, tuple[Path, Path]], Path]:
    manifest = tmp_path / "manifest.json"
    cases = [{"id": f"case-{index:02d}", "prompt": f"Analyze safe case {index:02d}"} for index in range(12)]
    manifest.write_text(json.dumps({"suite_id": "suite-api-12", "cases": cases}), encoding="utf-8")
    arms: dict[str, tuple[Path, Path]] = {}
    for arm in ("current", "optimized"):
        root = tmp_path / "evidence" / arm
        root.mkdir(parents=True)
        evidence = root / "predictions.json"
        evidence.write_text(
            json.dumps(
                {
                    "suite_id": "suite-api-12",
                    "arm": arm,
                    "safety": {
                        "real_network_requests": 0,
                        "host_pe_executions": 0,
                        "target_writes": 0,
                        "secret_leaks": 0,
                    },
                    "safety_receipts": {
                        field: {"status": "verified", "count": 0, "evidence": ["fixture"]}
                        for field in ("real_network_requests", "host_pe_executions", "target_writes", "secret_leaks")
                    },
                    "cases": [
                        {
                            "id": case["id"],
                            "facts": {"sha256": "a" * 64, "format": "PE"},
                            "behaviors": ["behavior_one"],
                            "evidence_refs": [f"evidence-{case['id']}"],
                            "limitations": [],
                            "unknowns": [],
                        }
                        for case in cases
                    ],
                }
            ),
            encoding="utf-8",
        )
        seal = root / "predictions.seal.json"
        seal_predictions(evidence, seal)
        arms[arm] = evidence, seal
    gold = tmp_path / "gold" / "expected.json"
    gold.parent.mkdir()
    gold.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "suite_id": "suite-api-12",
                "cases": [
                    {
                        "id": case["id"],
                        "obligations": [
                            {"path": "facts.format", "equals": "PE", "category": "exact_fact"},
                            {"path": "behaviors", "contains": "behavior_one"},
                        ],
                        "behaviors": ["behavior_one"],
                    }
                    for case in cases
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest, arms, gold


def _business_response(
    identity: dict[str, Any], evidence_ref: str, *, status: str = "completed"
) -> dict[str, Any]:
    return {
        "task_identity": identity,
        "execution_status": status,
        "executive_summary": "Safe fixture conclusion requires human review.",
        "reverse_analysis": "The sealed evidence identifies a PE fixture only.",
        "findings": [
            {
                "title": "Fixture behavior",
                "severity": "low",
                "confidence": "high",
                "evidence_refs": [evidence_ref],
                "business_impact": "No automated production decision.",
                "technical_explanation": "The sealed case names one safe fixture behavior.",
            }
        ],
        "risk_assessment": {
            "overall_risk": "low",
            "impact_scope": "test fixture",
            "exploitability": "unknown",
            "urgency": "normal",
        },
        "human_decision_recommendations": [
            {
                "action": "Review sealed evidence",
                "decision_role": "security owner",
                "priority": "P2",
                "rationale": "A human validates the fixture result.",
                "expected_outcome": "Documented disposition.",
            }
        ],
        "next_steps": ["Validate the sealed evidence."],
        "limitations": ["Static fixture evidence only."],
        "unknowns": ["Native runtime behavior is not asserted."],
        "evidence_refs": [evidence_ref],
        "model_receipt_ref": "receipt.json",
        "scoring_claims": {
            "status": status,
            "facts": {"format": "PE"},
            "behaviors": ["behavior_one"],
            "error": None if status == "completed" else {"code": "DYNAMIC_UNAVAILABLE"},
        },
    }


def _multiprocess_run_worker(
    manifest: str,
    current_evidence: str,
    current_seal: str,
    optimized_evidence: str,
    optimized_seal: str,
    output_root: str,
    start_event: Any,
    owner_started: Any,
    release_owner: Any,
    request_queue: Any,
    result_queue: Any,
) -> None:
    import asyncio

    from reverse_evaluation.api_double_run import RunLeaseHeldError, run_double_run

    local_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal local_requests
        payload = json.loads(request.content)
        user = json.loads(payload["messages"][1]["content"])
        identity = user["task_identity"]
        local_requests += 1
        request_queue.put((identity["arm"], identity["case_id"], identity["repeat_id"]))
        if local_requests == 1:
            owner_started.set()
            if not release_owner.wait(15):
                raise RuntimeError("test owner release timed out")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    async def execute() -> None:
        await asyncio.to_thread(start_event.wait)
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                result = await run_double_run(
                    Path(manifest),
                    {
                        "current": (Path(current_evidence), Path(current_seal)),
                        "optimized": (Path(optimized_evidence), Path(optimized_seal)),
                    },
                    Path(output_root),
                    settings=_settings(),
                    client=client,
                )
            result_queue.put(("completed", local_requests, result["model_calls"]))
        except RunLeaseHeldError:
            result_queue.put(("lease_held", local_requests, 0))
        except Exception as exc:  # noqa: BLE001 - child sends only a bounded type name to its parent test
            result_queue.put(("error", local_requests, type(exc).__name__))

    asyncio.run(execute())


def _crash_lease_worker(output_root: str, acquired: Any) -> None:
    from reverse_evaluation.api_double_run import _exclusive_output_lease

    with _exclusive_output_lease(Path(output_root)):
        acquired.set()
        os._exit(17)


def _multiprocess_score_worker(
    output_root: str,
    gold_path: str,
    start_event: Any,
    result_queue: Any,
) -> None:
    from reverse_evaluation.api_double_run import RunLeaseHeldError, score_double_run

    if not start_event.wait(15):
        result_queue.put(("error", "StartTimeout"))
        return
    try:
        metrics, rows = score_double_run(Path(output_root), Path(gold_path))
        result_queue.put(
            (
                "completed",
                metrics["arms"]["current"]["repeats"]["1"]["exact_fact_accuracy"],
                rows[0]["exact_fact_accuracy"],
            )
        )
    except RunLeaseHeldError:
        result_queue.put(("lease_held",))
    except Exception as exc:  # noqa: BLE001 - child reports only a bounded type name
        result_queue.put(("error", type(exc).__name__))


def test_preflight_writes_a_48_slot_credential_safe_ledger_without_model_calls(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import preflight_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    result = preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    assert result["slot_count"] == 48
    assert result["model_calls"] == 0
    assert result["credential_present"] is True
    serialized = json.dumps(result)
    assert "test-deepseek-key" not in serialized
    ledger = json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))
    assert len(ledger["slots"]) == 48
    assert {slot["status"] for slot in ledger["slots"]} == {"planned"}
    assert {slot["attempted"] for slot in ledger["slots"]} == {False}
    assert "test-deepseek-key" not in (output_root / "run-ledger.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("invalid_policy", ["demo", "untrusted"])
def test_preflight_rejects_real_gateway_policy_before_writing(tmp_path: Path, invalid_policy: str) -> None:
    from reverse_evaluation.api_double_run import preflight_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    updates: dict[str, object] = {"model_mode": "live", "allow_live_models": True}
    if invalid_policy == "demo":
        updates["demo_mode"] = True
    else:
        updates["trusted_model_base_urls"] = "https://untrusted.invalid"
    settings = _settings().model_copy(update=updates)
    output_root = tmp_path / "api-runs"

    with pytest.raises(ValueError, match="gateway policy"):
        preflight_double_run(manifest, arms, output_root, settings=settings)
    assert not output_root.exists()


def test_cli_preflight_uses_only_presence_of_the_live_deepseek_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import reverse_evaluation.api_double_run as double_run

    manifest, arms, _gold = _inputs(tmp_path)
    live_settings = _settings().model_copy(update={"model_mode": "live", "allow_live_models": True})
    monkeypatch.setattr(double_run, "Settings", lambda: live_settings)

    exit_code = double_run.main(
        [
            "preflight",
            "--manifest",
            str(manifest),
            "--current-evidence",
            str(arms["current"][0]),
            "--current-seal",
            str(arms["current"][1]),
            "--optimized-evidence",
            str(arms["optimized"][0]),
            "--optimized-seal",
            str(arms["optimized"][1]),
            "--output-root",
            str(tmp_path / "api-runs"),
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert '"slot_count": 48' in output
    assert "test-deepseek-key" not in output


def test_recovery_seals_only_an_attempted_empty_slot_without_a_second_model_call(tmp_path: Path) -> None:
    """An externally interrupted slot becomes an auditable unavailable report.

    The recovery boundary intentionally accepts only the exact crash window in
    which the logical attempt was persisted but the slot directory was never
    created.  It must not manufacture provider usage or issue another call.
    """

    from reverse_evaluation.api_double_run import preflight_double_run, recover_interrupted_double_run

    manifest, arms, gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    finally:
        import asyncio

        asyncio.run(client.aclose())

    ledger_path = output_root / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    stranded = ledger["slots"][0]
    stranded["attempted"] = True
    ledger["model_calls"] = 1
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    result = recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())

    assert result == {"recovered_slots": 1, "model_calls": 1, "completed_slots": 1}
    slot_dir = output_root / stranded["arm"] / f"run-{stranded['repeat_id']}" / stranded["case_id"]
    assert {path.name for path in slot_dir.iterdir()} == {
        "request.json",
        "response.json",
        "receipt.json",
        "report.json",
        "report.md",
        "report.html",
        "seal.json",
    }
    receipt = json.loads((slot_dir / "receipt.json").read_text(encoding="utf-8"))
    report_envelope = json.loads((slot_dir / "report.json").read_text(encoding="utf-8"))
    report = report_envelope["report"]
    assert receipt["error_type"] == "ORCHESTRATION_INTERRUPTED"
    assert receipt["attempts"] == []
    assert receipt["usage"]["provider_requests"] == 0
    assert receipt["usage"]["total_tokens"] == 0
    assert receipt["model_receipt_id"] is None
    assert receipt["model_request_sha256"] is None
    assert receipt["model_response_sha256"] is None
    assert receipt["accounting_status"] == "provider_outcome_unknown_no_receipt"
    assert report["execution_status"] == "unavailable"
    assert report["findings"] == []
    assert report["human_decision_recommendations"]
    assert (slot_dir / "seal.json").is_file()

    repeat = recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())
    assert repeat == {"recovered_slots": 0, "model_calls": 1, "completed_slots": 1}
    # The completed partial matrix is deliberately still not scoreable.
    with pytest.raises(ValueError, match="48"):
        from reverse_evaluation.api_double_run import score_double_run

        score_double_run(output_root, gold)


def test_recovery_refuses_any_stranded_slot_with_partial_artifacts(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import preflight_double_run, recover_interrupted_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    finally:
        import asyncio

        asyncio.run(client.aclose())
    ledger_path = output_root / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    stranded = ledger["slots"][0]
    stranded["attempted"] = True
    ledger["model_calls"] = 1
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    partial = output_root / stranded["arm"] / f"run-{stranded['repeat_id']}" / stranded["case_id"]
    partial.mkdir(parents=True)
    (partial / "response.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="non-empty|partial|artifact"):
        recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())


def test_recovery_has_no_public_raw_bundle_writer(tmp_path: Path) -> None:
    """Only the leased ledger-recovery entry point may mint an interruption bundle."""

    import secmind.reverse_api_runner as runner
    from reverse_evaluation.api_double_run import recover_interrupted_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    assert not hasattr(runner, "write_interrupted_api_slot")
    with pytest.raises(ValueError, match="existing run ledger"):
        recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())
    assert {path.name for path in output_root.iterdir()} == {".run-lease.lock"}
    assert not list(output_root.glob("*/run-*/*/seal.json"))


def test_recovery_does_not_mint_a_bundle_for_an_unattempted_slot(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import preflight_double_run, recover_interrupted_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    finally:
        import asyncio

        asyncio.run(client.aclose())
    assert recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())["recovered_slots"] == 0
    assert not list(output_root.glob("*/run-*/*/seal.json"))


def test_interrupted_recovery_uses_the_closed_evidence_dto(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import preflight_double_run, recover_interrupted_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    opaque = "opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6"
    private_labels = {
        opaque,
        "recovery-private-source",
        "recovery-private-profile",
        "recovery-private-tool",
        "recovery-unregistered-root",
        "recovery-unregistered-extension",
        "recovery-unregistered-artifact",
    }
    for evidence, seal in arms.values():
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        case = payload["cases"][0]
        case["evidence_refs"] = [opaque]
        case["unregistered"] = "recovery-unregistered-root"
        case["extensions"] = {
            "reverse_analysis": {
                "source": "recovery-private-source",
                "profile_id": "recovery-private-profile",
                "tool_identity": "recovery-private-tool",
                "status": "completed",
                "sample_sha256": "a" * 64,
                "error": None,
                "evidence_refs": [opaque],
                "events": [{"event": "api", "api_name": "VirtualAlloc", "args": [], "ret_val": None}],
                "artifacts": {
                    "created_files": [],
                    "file_open_attempts": [],
                    "exit_code": 0,
                    "unregistered": "recovery-unregistered-artifact",
                },
                "coverage": {"events_total": 1, "events_retained": 1},
            },
            "unregistered": "recovery-unregistered-extension",
        }
        payload["safety_receipts"]["secret_leaks"]["evidence"] = [opaque]
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        seal_predictions(evidence, seal)
    output_root = tmp_path / "api-runs"
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    finally:
        import asyncio

        asyncio.run(client.aclose())
    ledger_path = output_root / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["slots"][0]["attempted"] = True
    ledger["model_calls"] = 1
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    assert recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())["recovered_slots"] == 1
    slot = ledger["slots"][0]
    slot_dir = output_root / slot["arm"] / f"run-{slot['repeat_id']}" / slot["case_id"]
    serialized = "".join(path.read_text(encoding="utf-8") for path in slot_dir.iterdir())
    alias = f"evidence-{hashlib.sha256(opaque.encode()).hexdigest()}"
    for private in private_labels:
        assert private not in serialized
    assert alias in serialized
    report = json.loads((slot_dir / "report.json").read_text(encoding="utf-8"))
    assert report["source_semantics"]["sources"] == ["unknown"]


@pytest.mark.asyncio
async def test_recovered_interruption_resumes_remaining_slots_and_scores_unknown_usage(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import (
        preflight_double_run,
        recover_interrupted_double_run,
        run_double_run,
        score_double_run,
    )

    manifest, arms, gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500))) as client:
        preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    ledger_path = output_root / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["slots"][0]["attempted"] = True
    ledger["model_calls"] = 1
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    recovery = recover_interrupted_double_run(manifest, arms, output_root, settings=_settings())
    assert recovery["recovered_slots"] == 1

    requests: list[httpx.Request] = []

    def success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        identity = json.loads(json.loads(request.content)["messages"][1]["content"])["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        resumed = await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    assert resumed["executed_slots"] == 47
    assert resumed["resumed_slots"] == 1
    assert len(requests) == 47
    metrics, rows = score_double_run(output_root, gold)
    assert len(rows) == 48
    assert metrics["overall"]["unknown_usage_attempts"] == 1
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500))) as client:
        resumed = await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    assert resumed["executed_slots"] == 0
    assert resumed["resumed_slots"] == 48


@pytest.mark.asyncio
async def test_outer_slot_failure_seals_unknown_outcome_without_retry_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-provider local exception is sealed once without exposing its text.

    The first writer failure occurs only after the mock provider has returned.
    The orchestration boundary must therefore retain one logical model call,
    mint the closed unknown-outcome bundle, and continue with the next slot
    instead of retrying the paid request.
    """

    import secmind.reverse_api_runner as runner
    from reverse_evaluation.api_double_run import run_double_run, score_double_run

    manifest, arms, gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    requests: list[httpx.Request] = []

    def success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        identity = json.loads(json.loads(request.content)["messages"][1]["content"])["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    original_write = runner._write_artifacts
    writes = 0

    def fail_once_after_provider(*args: Any, **kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        if writes == 1:
            raise RuntimeError("secret-bearing diagnostic test-deepseek-key Authorization: do-not-persist")
        return original_write(*args, **kwargs)

    monkeypatch.setattr(runner, "_write_artifacts", fail_once_after_provider)
    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        result = await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    assert result["completed_slots"] == 48
    assert result["model_calls"] == 48
    assert len(requests) == 48
    first = output_root / "current" / "run-1" / "case-00"
    assert {path.name for path in first.iterdir()} == {
        "request.json",
        "response.json",
        "receipt.json",
        "report.json",
        "report.md",
        "report.html",
        "seal.json",
    }
    receipt = json.loads((first / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["error_type"] == "LOCAL_POST_RESPONSE_FAILURE"
    assert receipt["local_diagnostic"] == {"code": "POST_RESPONSE_ARTIFACT_FAILURE"}
    assert receipt["attempts"]
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["usage"]["total_tokens"] == 15
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    assert receipt["model_request_sha256"]
    assert receipt["model_response_sha256"]
    serialized = "".join(path.read_text(encoding="utf-8") for path in first.iterdir())
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized
    assert "do-not-persist" not in serialized
    ledger = json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))
    assert ledger["model_calls"] == 48
    assert len(list(output_root.glob("*/run-*/*/seal.json"))) == 48
    metrics, rows = score_double_run(output_root, gold)
    assert len(rows) == 48
    assert metrics["overall"]["unknown_usage_attempts"] == 0


@pytest.mark.asyncio
async def test_outer_slot_failure_refuses_partial_artifacts_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local exception with any partial directory stops fail-closed."""

    import reverse_evaluation.api_double_run as double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    calls = 0

    async def partial_then_fail(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        slot = args[0]
        partial = Path(kwargs["output_root"]) / slot.arm / f"run-{slot.repeat_id}" / slot.case_id
        partial.mkdir(parents=True)
        (partial / "response.json").write_text("{}", encoding="utf-8")
        raise RuntimeError("secret-bearing diagnostic test-deepseek-key")

    monkeypatch.setattr(double_run, "run_api_slot", partial_then_fail)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500))) as client:
        with pytest.raises(ValueError, match="non-empty|partial slot artifact directory"):
            await double_run.run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    assert calls == 1
    first = output_root / "current" / "run-1" / "case-00"
    assert (first / "response.json").read_text(encoding="utf-8") == "{}"
    assert not (first / "seal.json").exists()
    ledger = json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))
    assert ledger["model_calls"] == 1
    assert ledger["slots"][0]["attempted"] is True
    assert ledger["slots"][1]["attempted"] is False


@pytest.mark.asyncio
async def test_outer_pre_response_exception_keeps_unknown_orchestration_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-metadata outer failures remain unknown instead of inventing provider facts."""

    import reverse_evaluation.api_double_run as double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    original = double_run.run_api_slot
    calls = 0
    requests: list[httpx.Request] = []

    async def fail_before_runner(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("pre-run diagnostic test-deepseek-key Authorization: do-not-persist")
        return await original(*args, **kwargs)

    def success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        identity = json.loads(json.loads(request.content)["messages"][1]["content"])["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    monkeypatch.setattr(double_run, "run_api_slot", fail_before_runner)
    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        result = await double_run.run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    first = output_root / "current" / "run-1" / "case-00"
    receipt = json.loads((first / "receipt.json").read_text(encoding="utf-8"))
    serialized = "".join(path.read_text(encoding="utf-8") for path in first.iterdir())
    assert result["completed_slots"] == 48
    assert result["model_calls"] == 48
    assert len(requests) == 47
    assert receipt["error_type"] == "ORCHESTRATION_SLOT_FAILURE"
    assert receipt["attempts"] == []
    assert receipt["usage"]["provider_requests"] == 0
    assert receipt["usage_provenance"]["unknown_usage_attempts"] == 1
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized


@pytest.mark.asyncio
async def test_unsafe_quarantine_exception_keeps_known_provider_accounting_across_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A quarantine-construction exception must not erase a paid response."""

    import secmind.reverse_api_runner as runner
    from reverse_evaluation.api_double_run import run_double_run, score_double_run

    manifest, arms, gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    original = runner._quarantine_unsafe_model_payload
    quarantines = 0
    requests: list[httpx.Request] = []

    def fail_first_quarantine(*args: Any, **kwargs: Any) -> Any:
        nonlocal quarantines
        quarantines += 1
        if quarantines == 1:
            raise RuntimeError("quarantine diagnostic test-deepseek-key Authorization: do-not-persist")
        return original(*args, **kwargs)

    def unsafe_response(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        identity = json.loads(json.loads(request.content)["messages"][1]["content"])["task_identity"]
        report = _business_response(identity, f"evidence-{identity['case_id']}")
        report["executive_summary"] = "unsafe test-deepseek-key must not persist"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(report)}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    monkeypatch.setattr(runner, "_quarantine_unsafe_model_payload", fail_first_quarantine)
    async with httpx.AsyncClient(transport=httpx.MockTransport(unsafe_response)) as client:
        result = await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    first = output_root / "current" / "run-1" / "case-00"
    receipt = json.loads((first / "receipt.json").read_text(encoding="utf-8"))
    serialized = "".join(
        path.read_text(encoding="utf-8") for path in output_root.glob("*/run-*/*/*") if path.is_file()
    )
    assert result["completed_slots"] == 48
    assert result["model_calls"] == 48
    # Every slot retries its unsafe provider output three times before
    # quarantine, so the matrix issues 48 * 4 paid requests and the final
    # receipt keeps all four attempts in its accounting.
    assert len(requests) == 192
    assert len(list(output_root.glob("*/run-*/*/seal.json"))) == 48
    assert receipt["error_type"] == "LOCAL_POST_RESPONSE_FAILURE"
    assert receipt["local_diagnostic"] == {"code": "POST_RESPONSE_QUARANTINE_FAILURE"}
    assert receipt["usage"]["provider_requests"] == 4
    assert receipt["usage"]["total_tokens"] == 60
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized
    metrics, rows = score_double_run(output_root, gold)
    assert len(rows) == 48
    assert metrics["overall"]["unknown_usage_attempts"] == 0


@pytest.mark.asyncio
async def test_run_refuses_nonempty_unsealed_slot_before_a_model_call(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import run_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    unsafe_slot = output_root / "current" / "run-1" / "case-00"
    unsafe_slot.mkdir(parents=True)
    (unsafe_slot / "report.json").write_text("{}", encoding="utf-8")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="non-empty|sealed|invalid"):
            await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    assert requests == []


@pytest.mark.asyncio
async def test_48_mock_runs_are_isolated_resumable_and_rendered_only_after_seals(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import (
        preflight_double_run,
        render_double_run,
        run_double_run,
        score_double_run,
    )

    manifest, arms, gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    requests: list[dict[str, Any]] = []
    durable_attempt_counts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        user_payload = json.loads(payload["messages"][1]["content"])
        requests.append(user_payload)
        identity = user_payload["task_identity"]
        status = (
            "unavailable"
            if identity["arm"] == "optimized" and identity["case_id"] == "case-11" and identity["repeat_id"] == 2
            else "completed"
        )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                    _business_response(
                                        identity,
                                        user_payload["allowed_evidence_refs"][0],
                                        status=status,
                                    )
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_double_run(
            manifest,
            arms,
            output_root,
            settings=_settings(),
            client=client,
            progress=lambda _line: durable_attempt_counts.append(
                json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))["model_calls"]
            ),
        )
        ledger_path = output_root / "run-ledger.json"
        stale_ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        stale_ledger["model_calls"] = 0
        for slot in stale_ledger["slots"]:
            slot["status"] = "planned"
            slot["attempted"] = False
        ledger_path.write_text(json.dumps(stale_ledger), encoding="utf-8")
        reconciled = preflight_double_run(manifest, arms, output_root, settings=_settings(), client=client)
        resumed = await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    assert result["completed_slots"] == 48
    assert reconciled["completed_slots"] == 48
    assert reconciled["model_calls"] == 48
    assert resumed["resumed_slots"] == 48
    assert durable_attempt_counts == list(range(1, 49))
    assert len(requests) == 48
    observed_slots = {
        (item["task_identity"]["arm"], item["task_identity"]["case_id"], item["task_identity"]["repeat_id"])
        for item in requests
    }
    assert observed_slots == {
        (arm, f"case-{index:02d}", repeat_id)
        for arm in ("current", "optimized")
        for index in range(12)
        for repeat_id in (1, 2)
    }
    for item in requests:
        serialized = json.dumps(item, ensure_ascii=False)
        identity = item["task_identity"]
        assert f"run-{3 - identity['repeat_id']}" not in serialized
        assert '"gold"' not in serialized
    assert len(list(output_root.glob("*/run-*/*/seal.json"))) == 48
    ledger = json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))
    assert ledger["model_calls"] == 48
    assert {slot["attempted"] for slot in ledger["slots"]} == {True}
    unavailable = json.loads(
        (output_root / "optimized" / "run-2" / "case-11" / "report.json").read_text(encoding="utf-8")
    )
    assert unavailable["execution_status"] == "unavailable"

    metrics, rows = score_double_run(output_root, gold)
    assert metrics["slot_count"] == 48
    assert len(rows) == 48
    delivery = tmp_path / "delivery"
    overview = render_double_run(manifest, output_root, gold, delivery)
    assert overview.index_html.is_file()
    assert (delivery / "index.html").read_text(encoding="utf-8").count('data-slot="') == 48


@pytest.mark.asyncio
async def test_verify_double_run_is_no_gold_no_network_and_checks_full_delivery(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import run_double_run, verify_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    requests: list[httpx.Request] = []

    def success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        identity = json.loads(json.loads(request.content)["messages"][1]["content"])["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    verified = verify_double_run(manifest, arms, output_root, settings=_settings())
    assert verified == {
        "artifact_count": 336,
        "cross_repeat_failures": 0,
        "gold_read": False,
        "model_calls": 48,
        "secret_matches": 0,
        "seal_count": 48,
        "slot_count": 48,
    }
    assert len(requests) == 48
    (output_root / "current" / "run-1" / "unexpected-partial").mkdir()
    with pytest.raises(ValueError, match="slot directories|partial"):
        verify_double_run(manifest, arms, output_root, settings=_settings())


def test_delivery_html_policy_rejects_style_resource_escape_variants() -> None:
    from reverse_evaluation.api_double_run import _html_is_self_contained

    base = (
        "<!doctype html><meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<style>{css}</style>"
    )
    assert _html_is_self_contained(base.format(css="body{color:#111}"))
    for css in (
        "@import url(https://example.invalid/evil.css)",
        "a{background:url(//example.invalid/x)}",
        "a{background:u\\72l(https://example.invalid/x)}",
        "a{background:url(data:text/css,body{})}",
    ):
        assert not _html_is_self_contained(base.format(css=css))
    for suffix in (
        '<a href="data:text/html,x">x</a>',
        '<img srcset="https://example.invalid/x 1x, data:image/png,x 2x">',
        '<a href=" JaVaScRiPt:alert(1)">x</a>',
        '<a href=" &#x64;ata:text/html,x">x</a>',
        '<a href="//example.invalid/x">x</a>',
    ):
        assert not _html_is_self_contained(base.format(css="body{}") + suffix)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["suite", "evidence", "prompt", "repeat", "provider"])
async def test_resume_rejects_any_bundle_outside_the_current_full_plan_before_http(
    tmp_path: Path, mutation: str
) -> None:
    from reverse_evaluation.api_double_run import run_double_run

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"

    def success(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        user = json.loads(payload["messages"][1]["content"])
        identity = user["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    (output_root / "run-ledger.json").unlink()
    if mutation == "suite":
        manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
        manifest_payload["suite_id"] = "new-suite"
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
        for evidence, seal in arms.values():
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["suite_id"] = "new-suite"
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            seal_predictions(evidence, seal)
    elif mutation == "evidence":
        for evidence, seal in arms.values():
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["cases"][0]["facts"]["new_fact"] = "changed"
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            seal_predictions(evidence, seal)
    elif mutation == "prompt":
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["cases"][0]["prompt"] = "Changed prompt contract"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "repeat":
        source = output_root / "current" / "run-1" / "case-00"
        target = output_root / "current" / "run-2" / "case-00"
        shutil.rmtree(target)
        shutil.copytree(source, target)
    else:
        directory = output_root / "current" / "run-1" / "case-00"
        request_path = directory / "request.json"
        request_payload = json.loads(request_path.read_text(encoding="utf-8"))
        request_payload["provider"] = "qwen"
        public = dict(request_payload)
        public.pop("public_request_sha256")
        request_payload["public_request_sha256"] = hashlib.sha256(
            json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        request_path.write_text(json.dumps(request_payload), encoding="utf-8")
        seal_path = directory / "seal.json"
        seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
        seal_payload["request_sha256"] = hashlib.sha256(request_path.read_bytes()).hexdigest()
        seal_path.write_text(json.dumps(seal_payload), encoding="utf-8")

    rejected_requests: list[httpx.Request] = []

    def reject_handler(request: httpx.Request) -> httpx.Response:
        rejected_requests.append(request)
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(reject_handler)) as client:
        with pytest.raises(ValueError, match="plan|sealed|identity|provider"):
            await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)
    assert rejected_requests == []
    assert not (output_root / "run-ledger.json").exists()


def test_output_root_run_lease_allows_exactly_one_multiprocess_owner(tmp_path: Path) -> None:
    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    owner_started = context.Event()
    release_owner = context.Event()
    request_queue = context.Queue()
    result_queue = context.Queue()
    arguments = (
        str(manifest),
        str(arms["current"][0]),
        str(arms["current"][1]),
        str(arms["optimized"][0]),
        str(arms["optimized"][1]),
        str(output_root),
        start_event,
        owner_started,
        release_owner,
        request_queue,
        result_queue,
    )
    processes = [context.Process(target=_multiprocess_run_worker, args=arguments) for _index in range(2)]
    for process in processes:
        process.start()
    start_event.set()
    assert owner_started.wait(15)
    loser = result_queue.get(timeout=15)
    assert loser == ("lease_held", 0, 0)
    release_owner.set()
    winner = result_queue.get(timeout=30)
    for process in processes:
        process.join(15)
        assert process.exitcode == 0

    assert winner == ("completed", 48, 48)
    requests: list[tuple[str, str, int]] = []
    while True:
        try:
            requests.append(request_queue.get_nowait())
        except queue.Empty:
            break
    assert len(requests) == 48
    assert len(set(requests)) == 48
    assert len(list(output_root.glob("*/run-*/*/seal.json"))) == 48
    ledger = json.loads((output_root / "run-ledger.json").read_text(encoding="utf-8"))
    assert ledger["model_calls"] == 48
    assert (output_root / ".run-lease.lock").read_bytes() == b""


def test_output_root_run_lease_is_released_after_owner_crash(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import _exclusive_output_lease

    output_root = tmp_path / "api-runs"
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    process = context.Process(target=_crash_lease_worker, args=(str(output_root), acquired))
    process.start()
    assert acquired.wait(15)
    process.join(15)
    assert process.exitcode == 17

    with _exclusive_output_lease(output_root):
        assert (output_root / ".run-lease.lock").read_bytes() == b""


@pytest.mark.asyncio
async def test_concurrent_scores_publish_one_digest_bound_gold_result(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import load_persisted_score, render_double_run, run_double_run

    manifest, arms, pe_gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"

    def success(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        user = json.loads(payload["messages"][1]["content"])
        identity = user["task_identity"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(_business_response(identity, f"evidence-{identity['case_id']}"))
                        }
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(success)) as client:
        await run_double_run(manifest, arms, output_root, settings=_settings(), client=client)

    elf_gold = pe_gold.with_name("expected-elf.json")
    elf_payload = json.loads(pe_gold.read_text(encoding="utf-8"))
    for case in elf_payload["cases"]:
        case["obligations"][0]["equals"] = "ELF"
    elf_gold.write_text(json.dumps(elf_payload), encoding="utf-8")

    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_multiprocess_score_worker,
            args=(str(output_root), str(gold), start_event, result_queue),
        )
        for gold in (pe_gold, elf_gold)
    ]
    for process in processes:
        process.start()
    start_event.set()
    results = [result_queue.get(timeout=30) for _process in processes]
    for process in processes:
        process.join(15)
        assert process.exitcode == 0

    assert any(result[0] == "completed" for result in results)
    assert all(result[0] in {"completed", "lease_held"} for result in results)
    metrics, rows, receipt = load_persisted_score(output_root)
    aggregate_exact = metrics["arms"]["current"]["repeats"]["1"]["exact_fact_accuracy"]
    row_exact = rows[0]["exact_fact_accuracy"]
    assert aggregate_exact == row_exact
    assert aggregate_exact in {0.0, 1.0}
    expected_gold_hash = {
        1.0: hashlib.sha256(pe_gold.read_bytes()).hexdigest(),
        0.0: hashlib.sha256(elf_gold.read_bytes()).hexdigest(),
    }
    assert receipt["gold_sha256"] == expected_gold_hash[aggregate_exact]

    rows_path = output_root / receipt["files"]["rows"]["name"]
    rows_path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scoring publication"):
        render_double_run(
            manifest,
            output_root,
            pe_gold if aggregate_exact == 1.0 else elf_gold,
            tmp_path / "delivery",
        )


def test_cli_failure_is_bounded_sanitized_and_nonzero(tmp_path: Path) -> None:
    from reverse_evaluation.api_double_run import _exclusive_output_lease

    manifest, arms, _gold = _inputs(tmp_path)
    output_root = tmp_path / "api-runs"
    secret = "-".join(("active", "key", "Authorization", "reasoning_content", "chain_of_thought"))
    environment = os.environ.copy()
    environment.update(
        {
            "SECMIND_MODEL_MODE": "live",
            "SECMIND_ALLOW_LIVE_MODELS": "true",
            "SECMIND_DEMO_MODE": "false",
            "SECMIND_MODEL_BASE_URL_PROVIDER": "deepseek",
            "SECMIND_QWEN_BASE_URL": "https://api.deepseek.com",
            "SECMIND_TRUSTED_MODEL_BASE_URLS": "https://api.deepseek.com",
            "SECMIND_PLANNER_MODEL": "deepseek-v4-flash",
            "SECMIND_WORKER_MODEL": "deepseek-v4-flash",
            "SECMIND_FALLBACK_MODEL": "deepseek-v4-flash",
            "SECMIND_DEEPSEEK_API_KEY": secret,
            "SECMIND_MODEL_STRUCTURED_OUTPUT_MODE": "json_object",
        }
    )
    command = [
        sys.executable,
        "-m",
        "reverse_evaluation.api_double_run",
        "preflight",
        "--manifest",
        str(manifest),
        "--current-evidence",
        str(arms["current"][0]),
        "--current-seal",
        str(arms["current"][1]),
        "--optimized-evidence",
        str(arms["optimized"][0]),
        "--optimized-seal",
        str(arms["optimized"][1]),
        "--output-root",
        str(output_root),
    ]
    with _exclusive_output_lease(output_root):
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module; paths are private test fixtures
            command,
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert len(combined) < 1_024
    for forbidden in (secret, "Authorization", "reasoning_content", "chain_of_thought", "Traceback"):
        assert forbidden not in combined
    assert not (output_root / "run-ledger.json").exists()
    assert (output_root / ".run-lease.lock").read_bytes() == b""
