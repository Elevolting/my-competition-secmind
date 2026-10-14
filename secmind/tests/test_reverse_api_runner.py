from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import httpx
import pytest

from secmind.config import Settings
from secmind.reverse_api_business import TaskIdentity
from secmind.reverse_api_slots import ApiRunSlot
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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _slot_inputs(tmp_path: Path, *, repeat_id: int = 1) -> tuple[ApiRunSlot, Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "suite_id": "suite-api",
                "cases": [
                    {"id": "case-one", "prompt": "Analyze only this safe fixture"},
                    {"id": "case-two", "prompt": "SIBLING-CASE-MUST-NOT-APPEAR"},
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "predictions.json"
    evidence.write_text(
        json.dumps(
            {
                "suite_id": "suite-api",
                "arm": "current",
                "cases": [
                    {
                        "id": "case-one",
                        "facts": {"sha256": "a" * 64, "format": "PE"},
                        "behaviors": ["safe_behavior"],
                        "evidence_refs": ["evidence-case-one"],
                        "limitations": [],
                        "unknowns": [],
                    },
                    {
                        "id": "case-two",
                        "facts": {"sha256": "b" * 64},
                        "behaviors": [],
                        "evidence_refs": ["sibling-evidence"],
                        "limitations": [],
                        "unknowns": [],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    seal = tmp_path / "predictions.seal.json"
    seal_predictions(evidence, seal)
    slot = ApiRunSlot(
        arm="current",
        case_id="case-one",
        repeat_id=repeat_id,
        evidence_sha256=json.loads(seal.read_text(encoding="utf-8"))["prediction_sha256"],
        prompt_sha256=_sha256_text("Analyze only this safe fixture"),
    )
    return slot, manifest, evidence, seal


def _business_response(*, repeat_id: int = 1, evidence_refs: list[str] | None = None) -> dict[str, object]:
    return {
        "task_identity": {
            "suite_id": "suite-api",
            "arm": "current",
            "case_id": "case-one",
            "repeat_id": repeat_id,
            "sample_sha256": "a" * 64,
            "provider": "deepseek",
            "model": "deepseek-v4-flash",
        },
        "execution_status": "completed",
        "executive_summary": "Safe test conclusion for a security owner.",
        "reverse_analysis": "The sealed static evidence identifies a PE fixture.",
        "findings": [
            {
                "title": "Fixture format",
                "severity": "low",
                "confidence": "high",
                "evidence_refs": evidence_refs or ["evidence-case-one"],
                "business_impact": "No production decision is automated.",
                "technical_explanation": "Evidence identifies the declared fixture format.",
            }
        ],
        "risk_assessment": {
            "overall_risk": "low",
            "impact_scope": "test fixture",
            "exploitability": "not assessed",
            "urgency": "normal",
        },
        "human_decision_recommendations": [
            {
                "action": "Review the sealed evidence",
                "decision_role": "security owner",
                "priority": "P2",
                "rationale": "A human should validate the test conclusion.",
                "expected_outcome": "A documented disposition.",
            }
        ],
        "next_steps": ["Validate the finding against the sealed evidence."],
        "limitations": ["Static evidence only."],
        "unknowns": ["Runtime behavior is not asserted."],
        "evidence_refs": evidence_refs or ["evidence-case-one"],
        "model_receipt_ref": "receipt.json",
        "scoring_claims": {
            "status": "completed",
            "facts": {"format": "PE"},
            "behaviors": ["safe_behavior"],
            "error": None,
        },
    }


@pytest.mark.asyncio
async def test_single_slot_uses_only_its_case_and_deepseek_identity(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(evidence_refs=[model_input["allowed_evidence_refs"][0]])
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert len(requests) == 1
    assert requests[0].url.host == "api.deepseek.com"
    assert requests[0].headers["Authorization"] == "Bearer test-deepseek-key"
    request_payload = json.loads(requests[0].content)
    assert request_payload["model"] == "deepseek-v4-flash"
    serialized_request = json.dumps(request_payload, ensure_ascii=False)
    for forbidden in ("case-two", "SIBLING-CASE-MUST-NOT-APPEAR", "sibling-evidence", "gold", "qwen-must-not-be-used"):
        assert forbidden not in serialized_request
    assert result.report.execution_status == "completed"
    assert result.output_dir == tmp_path / "api-runs" / "current" / "run-1" / "case-one"


@pytest.mark.asyncio
async def test_valid_sample_digest_stays_only_in_task_identity_not_technical_facts(tmp_path: Path) -> None:
    """A real SHA256 sample identity must not trip the generic public scanner."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    sample_sha256 = hashlib.sha256(b"real-shape-sample-identity").hexdigest()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["cases"][0]["facts"]["sha256"] = sample_sha256
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    seal_predictions(evidence, seal)
    slot = ApiRunSlot(
        arm=slot.arm,
        case_id=slot.case_id,
        repeat_id=slot.repeat_id,
        evidence_sha256=json.loads(seal.read_text(encoding="utf-8"))["prediction_sha256"],
        prompt_sha256=slot.prompt_sha256,
    )
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        seen.update(model_input)
        response = _business_response(evidence_refs=[model_input["allowed_evidence_refs"][0]])
        response["task_identity"]["sample_sha256"] = model_input["task_identity"]["sample_sha256"]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(response)}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    sealed_evidence = seen["sealed_evidence"]
    assert isinstance(sealed_evidence, dict)
    assert sample_sha256 not in json.dumps(sealed_evidence, ensure_ascii=False)
    assert seen["task_identity"]["sample_sha256"] == sample_sha256
    assert result.report.task_identity.sample_sha256 == sample_sha256


def test_evidence_dto_rejects_malformed_or_conflicting_sample_identity(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import _public_evidence_projection

    _slot, _manifest, evidence, _seal = _slot_inputs(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    case = payload["cases"][0]
    identity = TaskIdentity(
        suite_id="suite-api",
        arm="current",
        case_id="case-one",
        repeat_id=1,
        sample_sha256="a" * 64,
        provider="deepseek",
        model="deepseek-v4-flash",
    )
    malformed = {**case, "facts": {**case["facts"], "sha256": "not-a-digest"}}
    conflicting = {**case, "facts": {**case["facts"], "sha256": "b" * 64}}

    with pytest.raises(ValueError, match="facts.sha256"):
        _public_evidence_projection(malformed, payload, identity)
    with pytest.raises(ValueError, match="conflicts"):
        _public_evidence_projection(conflicting, payload, identity)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    (
        "facts",
        "reverse",
        "observation",
        "case_safety",
        "case_safety_task_identity",
        "evidence_safety",
        "receipt_safety",
        "artifact",
    ),
)
async def test_duplicate_sample_identity_conflicts_fail_before_model_or_artifact(
    tmp_path: Path, location: str
) -> None:
    """Every declared sample identity is bound before a public/API boundary."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    case = payload["cases"][0]
    conflict = "b" * 64
    dynamic = {
        "source": "speakeasy",
        "profile_id": "test-profile",
        "tool_identity": {"name": "speakeasy", "version": "test"},
        "status": "completed",
        "sample_sha256": "a" * 64,
        "error": None,
        "evidence_refs": ["evidence-case-one"],
        "events": [{"event": "api", "api_name": "VirtualAlloc", "args": [], "ret_val": None}],
        "artifacts": {"created_files": [], "file_open_attempts": [], "exit_code": 0},
        "coverage": {"events_total": 1, "events_retained": 1},
    }
    if location in {"reverse", "artifact"}:
        case["extensions"] = {"reverse_analysis": dynamic}
    if location == "facts":
        case["facts"]["sha256"] = "not-a-sha256"
    elif location == "reverse":
        dynamic["sample_sha256"] = conflict
    elif location == "observation":
        case["observations"] = [{"sample_sha256": conflict}]
    elif location == "case_safety":
        case["safety_observation"] = {"sample_sha256": conflict}
    elif location == "case_safety_task_identity":
        case["safety_observation"] = {"task_identity": {"sample_sha256": conflict}}
    elif location == "evidence_safety":
        payload["safety_observation"] = {"sample_sha256": conflict}
    elif location == "receipt_safety":
        payload.setdefault(
            "safety_receipts",
            {
                "secret_leaks": {"status": "verified", "count": 0, "evidence": ["fixture"]},
            },
        )
        payload["safety_receipts"]["secret_leaks"]["sample_sha256"] = conflict
    else:
        dynamic["artifacts"]["sample_sha256"] = conflict
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    seal_predictions(evidence, seal)
    slot = ApiRunSlot(
        arm=slot.arm,
        case_id=slot.case_id,
        repeat_id=slot.repeat_id,
        evidence_sha256=json.loads(seal.read_text(encoding="utf-8"))["prediction_sha256"],
        prompt_sha256=slot.prompt_sha256,
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="sha256|sample"):
            await run_api_slot(
                slot,
                manifest_path=manifest,
                evidence_path=evidence,
                evidence_seal_path=seal,
                output_root=tmp_path / "api-runs",
                settings=_settings(),
                client=client,
            )

    assert requests == []
    assert not (tmp_path / "api-runs" / "current" / "run-1" / "case-one").exists()


def test_all_real_sealed_cases_pass_normal_and_recovery_public_safety_gates() -> None:
    """Both public payload paths are safe for every actual sealed case shape."""

    from secmind.reverse_api_case_report import assert_safe_deliverable_payload
    from secmind.reverse_api_runner import (
        _public_evidence_projection,
        _request_record,
        _require_slot_case,
        _safety_observation,
    )

    root = Path(__file__).parents[1] / "reverse_evaluation"
    manifest_path = root / "cases" / "manifest.json"
    for arm in ("current", "optimized"):
        evidence_path = root / "evidence" / "deepseek-api-2026-08-24" / arm / "predictions.json"
        seal_path = evidence_path.with_name("predictions.seal.json")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence_sha256 = json.loads(seal_path.read_text(encoding="utf-8"))["prediction_sha256"]
        prompts = {
            item["id"]: item["prompt"]
            for item in json.loads(manifest_path.read_text(encoding="utf-8"))["cases"]
        }
        for case in evidence["cases"]:
            case_id = case["id"]
            slot = ApiRunSlot(
                arm=arm,
                case_id=case_id,
                repeat_id=1,
                evidence_sha256=evidence_sha256,
                prompt_sha256=_sha256_text(prompts[case_id]),
            )
            prompt, _manifest_case, sealed_evidence, sealed_case, identity = _require_slot_case(
                slot, manifest_path, evidence_path, seal_path
            )
            dto = _public_evidence_projection(sealed_case, sealed_evidence, identity)
            safety = _safety_observation(sealed_evidence, identity, aliases=dto.aliases, reverse=dto.reverse)
            normal_request, _ = _request_record(slot, identity, prompt, sealed_case, safety, dto.allowed_refs)
            recovery_request, _ = _request_record(slot, identity, prompt, sealed_case, safety, dto.allowed_refs)
            assert sealed_case["facts"].get("sha256", identity.sample_sha256) == identity.sample_sha256
            assert "sha256" not in dto.case["facts"]
            reverse = dto.case.get("extensions", {}).get("reverse_analysis", {})
            assert "sample_sha256" not in reverse
            assert_safe_deliverable_payload(dto.case, active_secret=_settings().model_api_key_value("deepseek"))
            assert_safe_deliverable_payload(normal_request, active_secret=_settings().model_api_key_value("deepseek"))
            assert_safe_deliverable_payload(recovery_request, active_secret=_settings().model_api_key_value("deepseek"))


@pytest.mark.asyncio
async def test_slot_writes_seven_sealed_artifacts_and_keeps_repeats_isolated(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import ARTIFACT_NAMES, run_api_slot

    slot_one, manifest, evidence, seal = _slot_inputs(tmp_path, repeat_id=1)
    slot_two, _, _, _ = _slot_inputs(tmp_path / "second-input", repeat_id=2)

    def handler(request: httpx.Request) -> httpx.Response:
        user_content = json.loads(json.loads(request.content)["messages"][1]["content"])
        repeat_id = user_content["task_identity"]["repeat_id"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(
                                    repeat_id=repeat_id,
                                    evidence_refs=[user_content["allowed_evidence_refs"][0]],
                                )
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first = await run_api_slot(
            slot_one,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )
        second = await run_api_slot(
            slot_two,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert {path.name for path in first.artifacts.values()} == set(ARTIFACT_NAMES)
    assert {path.name for path in second.artifacts.values()} == set(ARTIFACT_NAMES)
    first_response_digest = hashlib.sha256(first.artifacts["response.json"].read_bytes()).hexdigest()
    first_report = first.artifacts["report.json"].read_text(encoding="utf-8")
    second_serialized = "".join(path.read_text(encoding="utf-8") for path in second.artifacts.values())
    assert first_response_digest not in second_serialized
    assert first_report not in second_serialized
    seal_payload = json.loads(second.artifacts["seal.json"].read_text(encoding="utf-8"))
    assert seal_payload["suite_id"] == "suite-api"
    assert seal_payload["arm"] == "current"
    assert seal_payload["case_id"] == "case-one"
    assert seal_payload["repeat_id"] == 2
    for field in (
        "request_sha256",
        "response_sha256",
        "receipt_sha256",
        "report_json_sha256",
        "report_md_sha256",
        "report_html_sha256",
    ):
        assert len(seal_payload[field]) == 64
    request_record = second.artifacts["request.json"].read_text(encoding="utf-8")
    assert "Authorization" not in request_record
    assert "test-deepseek-key" not in request_record


@pytest.mark.asyncio
async def test_provider_failure_still_writes_unavailable_business_report(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import ARTIFACT_NAMES, run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "maintenance"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert result.report.execution_status == "unavailable"
    assert result.report.human_decision_recommendations
    assert result.report.next_steps
    assert {path.name for path in result.artifacts.values()} == set(ARTIFACT_NAMES)
    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert receipt["error_type"] == "MODEL_GATEWAY_ERROR"
    assert isinstance(receipt["attempts"], list)
    assert receipt["model_receipt_id"] is None
    assert receipt["model_request_sha256"] is None
    assert receipt["model_response_sha256"] is None


@pytest.mark.asyncio
async def test_opaque_evidence_references_are_projected_before_model_and_public_artifacts(tmp_path: Path) -> None:
    """Sealed opaque labels stay private while reports use deterministic aliases."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    opaque_ref = "opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6"
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["cases"][0]["evidence_refs"] = [opaque_ref]
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    seal_predictions(evidence, seal)
    slot = ApiRunSlot(
        arm=slot.arm,
        case_id=slot.case_id,
        repeat_id=slot.repeat_id,
        evidence_sha256=json.loads(seal.read_text(encoding="utf-8"))["prediction_sha256"],
        prompt_sha256=slot.prompt_sha256,
    )
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        seen.update(model_input)
        alias = model_input["allowed_evidence_refs"][0]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(_business_response(evidence_refs=[alias]))}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert seen["allowed_evidence_refs"] == [f"evidence-{hashlib.sha256(opaque_ref.encode()).hexdigest()}"]
    assert opaque_ref not in json.dumps(seen, ensure_ascii=False)
    serialized = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert opaque_ref not in serialized
    assert result.report.evidence_refs == seen["allowed_evidence_refs"]


@pytest.mark.asyncio
async def test_all_registered_internal_identifiers_are_projected_before_model_and_reports(tmp_path: Path) -> None:
    """Short labels are private too; publicness is schema-based, not entropy-based."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    private_values = {
        "short-source-label",
        "tool-opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6",
        "profile-internal",
        "receipt-internal",
        "artifact-internal",
        "nested-evidence-internal",
        "unregistered-root-private",
        "unregistered-extension-private",
        "unregistered-coverage-private",
        "unregistered-artifact-private",
        "unregistered-error-private",
        "event-private-source-path",
        "event-opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6",
        "event-private-nested-extra",
    }
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["cases"][0]["facts"].update(
        {
            "source": "ordinary-technical-source-fact",
            "tool": "ordinary-technical-tool-fact",
            "profile": "ordinary-technical-profile-fact",
            "artifact": "ordinary-technical-artifact-fact",
        }
    )
    payload["cases"][0]["extensions"] = {
        "reverse_analysis": {
            "source": "short-source-label",
            "tool_identity": "tool-opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6",
            "profile_id": "profile-internal",
            "receipt": "receipt-internal",
            "artifact": "artifact-internal",
            "evidence_refs": ["nested-evidence-internal"],
            "status": "completed",
            "sample_sha256": "a" * 64,
            "events": [
                {
                    "event": "api_call",
                    "api_name": "VirtualAlloc",
                    "args": [],
                    "ret_val": None,
                    "source": "ordinary-event-source-fact",
                    "tool": "ordinary-event-tool-fact",
                    "source_paths": [
                        "event-private-source-path",
                        "event-opaque-7hY3uP1nQ8vR4xK2mD9sL5cA0wE6gT1bN8jF3qZ7rV4pX9kM2dH6",
                    ],
                    "nested_extra": {"receipt": "event-private-nested-extra"},
                }
            ],
            "artifacts": {
                "created_files": ["artifact-internal"],
                "file_open_attempts": [],
                "exit_code": 0,
                "unregistered": "unregistered-artifact-private",
            },
            "coverage": {
                "events_total": 1,
                "events_retained": 1,
                "unregistered": "unregistered-coverage-private",
            },
            "error": {"code": "DYNAMIC_UNAVAILABLE", "message": "unregistered-error-private"},
            "unknown_nested": {"source": "must-drop-at-every-level"},
        }
    }
    payload["cases"][0]["observations"] = [
        {"source": "must-drop-root-observations", "sample_sha256": "a" * 64}
    ]
    payload["cases"][0]["unregistered"] = "unregistered-root-private"
    payload["cases"][0]["extensions"]["unregistered"] = "unregistered-extension-private"
    private_values.update({"must-drop-at-every-level", "must-drop-root-observations"})
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    seal_predictions(evidence, seal)
    slot = ApiRunSlot(
        arm=slot.arm,
        case_id=slot.case_id,
        repeat_id=slot.repeat_id,
        evidence_sha256=json.loads(seal.read_text(encoding="utf-8"))["prediction_sha256"],
        prompt_sha256=slot.prompt_sha256,
    )
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        seen.update(model_input)
        alias = model_input["allowed_evidence_refs"][0]
        response = _business_response(evidence_refs=[alias])
        if "event-private-source-path" in json.dumps(model_input, ensure_ascii=False):
            # A permissive mock model can echo an unregistered short label;
            # the boundary, not the generic secret scanner, must prevent it.
            response["executive_summary"] = "Echo: event-private-source-path"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(response)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    model_serialized = json.dumps(seen, ensure_ascii=False)
    artifact_serialized = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    for private in private_values:
        assert private not in model_serialized
        assert private not in artifact_serialized
    source_semantics = json.loads(result.artifacts["report.json"].read_text(encoding="utf-8"))["source_semantics"]
    assert source_semantics["sources"] == ["unknown"]
    for ordinary_fact in (
        "ordinary-technical-source-fact",
        "ordinary-technical-tool-fact",
        "ordinary-technical-profile-fact",
        "ordinary-technical-artifact-fact",
        "ordinary-event-source-fact",
        "ordinary-event-tool-fact",
    ):
        assert ordinary_fact in model_serialized


@pytest.mark.asyncio
async def test_out_of_packet_evidence_reference_is_removed_and_marks_report_partial(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(
                                    evidence_refs=[model_input["allowed_evidence_refs"][0], "outside-packet"]
                                )
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert result.report.execution_status == "partial"
    alias = f"evidence-{hashlib.sha256(b'evidence-case-one').hexdigest()}"
    assert result.report.evidence_refs == [alias]
    assert result.report.findings[0].evidence_refs == [alias]
    assert any("封存证据包之外" in item for item in result.report.limitations)


@pytest.mark.asyncio
async def test_post_response_identity_rejection_preserves_deepseek_receipt_accounting(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    response = _business_response()
    identity = response["task_identity"]
    assert isinstance(identity, dict)
    identity["case_id"] = "wrong-case"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(response)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    response_record = json.loads(result.artifacts["response.json"].read_text(encoding="utf-8"))
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "STRUCTURED_OUTPUT_INVALID"
    assert receipt["model_receipt_id"]
    assert receipt["model_request_sha256"]
    assert receipt["model_response_sha256"]
    assert receipt["usage"]["provider_requests"] >= 1
    assert receipt["usage"]["total_tokens"] == 120
    assert response_record["model_response_sha256"] == receipt["model_response_sha256"]


@pytest.mark.asyncio
async def test_receipt_construction_failure_is_a_closed_local_post_response_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A paid response retains its safe accounting when local receipt binding fails."""

    import secmind.reverse_api_runner as runner
    from secmind.reverse_api_runner import run_api_slot
    from secmind.reverse_api_score import _validate_receipt_accounting

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    original = runner._response_bound_receipt_identity
    calls = 0

    def fail_once(*args: object, **kwargs: object) -> tuple[str | None, str, str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("receipt diagnostic test-deepseek-key Authorization: do-not-persist")
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "_response_bound_receipt_identity", fail_once)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(_business_response())}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    request = json.loads(result.artifacts["request.json"].read_text(encoding="utf-8"))
    serialized = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "LOCAL_POST_RESPONSE_FAILURE"
    assert receipt["local_diagnostic"] == {"code": "POST_RESPONSE_RECEIPT_FAILURE"}
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["usage"]["total_tokens"] == 120
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    assert _validate_receipt_accounting(receipt, request) == 0
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized
    assert calls == 1


@pytest.mark.asyncio
async def test_render_failure_replaces_paid_response_with_safe_local_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A renderer exception before directory creation cannot lose paid accounting."""

    import secmind.reverse_api_runner as runner
    from secmind.reverse_api_runner import run_api_slot
    from secmind.reverse_api_score import _validate_receipt_accounting

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    original = runner.render_case_html
    renders = 0

    def fail_once(*args: object, **kwargs: object) -> str:
        nonlocal renders
        renders += 1
        if renders == 1:
            raise RuntimeError("render diagnostic test-deepseek-key Authorization: do-not-persist")
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "render_case_html", fail_once)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(_business_response())}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    request = json.loads(result.artifacts["request.json"].read_text(encoding="utf-8"))
    serialized = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "LOCAL_POST_RESPONSE_FAILURE"
    assert receipt["local_diagnostic"] == {"code": "POST_RESPONSE_ARTIFACT_FAILURE"}
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["usage"]["total_tokens"] == 120
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    assert _validate_receipt_accounting(receipt, request) == 0
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized
    assert renders == 2


@pytest.mark.asyncio
async def test_paid_invalid_schema_retains_usage_pricing_and_safe_receipt(tmp_path: Path) -> None:
    """A paid HTTP 200 remains auditable even when its report schema is invalid."""

    from secmind.reverse_api_runner import run_api_slot
    from secmind.reverse_api_score import _validate_receipt_accounting

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"bad": "schema"})}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            headers={"x-request-id": "paid-invalid-schema"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    request_record = json.loads(result.artifacts["request.json"].read_text(encoding="utf-8"))
    response = json.loads(result.artifacts["response.json"].read_text(encoding="utf-8"))
    serialized_artifacts = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert len(requests) == 1
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "STRUCTURED_OUTPUT_INVALID"
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["usage"]["input_tokens"] == 100
    assert receipt["usage"]["output_tokens"] == 20
    assert receipt["usage"]["total_tokens"] == 120
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    assert receipt["model_request_sha256"]
    assert receipt["model_response_sha256"]
    assert response["model_response_sha256"] == receipt["model_response_sha256"]
    assert receipt["attempts"]
    provider_attempt = next(attempt for attempt in receipt["attempts"] if attempt["provider_request"])
    assert provider_attempt["request_digest"] == receipt["model_request_sha256"]
    assert provider_attempt["response_digest"] == receipt["model_response_sha256"]
    assert provider_attempt["logical_call_id"] == receipt["model_receipt_id"]
    assert provider_attempt["usage"]["input_tokens"] + provider_attempt["usage"]["output_tokens"] == 120
    provenance_usage = receipt["usage_provenance"]["provider_reported_usage"]
    assert provenance_usage["input_tokens"] + provenance_usage["output_tokens"] == 120
    assert _validate_receipt_accounting(receipt, request_record) == 0
    assert "test-deepseek-key" not in serialized_artifacts
    assert "Authorization" not in serialized_artifacts


@pytest.mark.asyncio
async def test_invalid_provider_usage_is_sealed_as_explicit_conservative_usage(tmp_path: Path) -> None:
    """Missing provider counters cannot make a paid schema failure look free."""

    from secmind.reverse_api_runner import run_api_slot
    from secmind.reverse_api_score import _validate_receipt_accounting

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({"bad": "schema"})}}]},
            headers={"x-request-id": "conservative-invalid-schema"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    request_record = json.loads(result.artifacts["request.json"].read_text(encoding="utf-8"))
    provenance = receipt["usage_provenance"]
    assert receipt["error_type"] == "STRUCTURED_OUTPUT_INVALID"
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["usage"]["total_tokens"] > 0
    assert receipt["pricing"]["estimated_cny"] > 0
    assert provenance["unknown_usage_attempts"] >= 1
    assert provenance["provider_reported_usage"]["provider_requests"] == 0
    assert provenance["conservative_reserved_usage"]["provider_requests"] == 1
    assert _validate_receipt_accounting(receipt, request_record) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_value",
    ["test-deepseek-key", "Authorization: Bearer foreign-token-value-1234567890"],
)
async def test_unsafe_model_payload_writes_sealed_unavailable_bundle_without_secret(
    tmp_path: Path,
    unsafe_value: str,
) -> None:
    from secmind.reverse_api_runner import ARTIFACT_NAMES, run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    unsafe_response = _business_response()
    unsafe_response["executive_summary"] = f"This must not persist: {unsafe_value}"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(unsafe_response)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
        )

    assert result.report.execution_status == "unavailable"
    assert {path.name for path in result.artifacts.values()} == set(ARTIFACT_NAMES)
    artifact_text = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert unsafe_value not in artifact_text
    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert receipt["execution_status"] == "unavailable"
    assert receipt["error_type"] == "UNSAFE_MODEL_PAYLOAD"
    assert receipt["attempts"]
    assert receipt["usage"]["provider_requests"] == 1
    assert receipt["pricing"]["estimated_cny"] > 0
    assert receipt["model_receipt_id"]
    for format_name in ("report.json", "report.md", "report.html"):
        report_text = result.artifacts[format_name].read_text(encoding="utf-8")
        assert "unavailable" in report_text
        assert "自动化结论不可用" in report_text
        assert "人工验证" in report_text
    seal_payload = json.loads(result.artifacts["seal.json"].read_text(encoding="utf-8"))
    assert seal_payload["report_json_sha256"]


@pytest.mark.asyncio
async def test_all_hex_active_secret_in_model_payload_is_quarantined_and_sealed(tmp_path: Path) -> None:
    from secmind.reverse_api_runner import ARTIFACT_NAMES, run_api_slot

    active_secret = "b" * 64
    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    unsafe_response = _business_response()
    unsafe_response["executive_summary"] = active_secret

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(unsafe_response)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    settings = _settings().model_copy(update={"deepseek_api_key": active_secret})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=settings,
            client=client,
        )

    assert result.report.execution_status == "unavailable"
    assert {path.name for path in result.artifacts.values()} == set(ARTIFACT_NAMES)
    artifact_text = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert active_secret not in artifact_text
    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert receipt["error_type"] == "UNSAFE_MODEL_PAYLOAD"


@pytest.mark.asyncio
@pytest.mark.parametrize("use_symlink", [False, True])
async def test_gold_evidence_is_rejected_without_any_read_http_or_artifact_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    use_symlink: bool,
) -> None:
    import secmind.reverse_api_runner as runner

    slot, manifest, evidence, seal = _slot_inputs(tmp_path / "safe-input")
    gold = tmp_path / "GoLd"
    gold.mkdir()
    gold_prediction = gold / "predictions.json"
    gold_seal = gold / "predictions.seal.json"
    gold_prediction.write_bytes(evidence.read_bytes())
    gold_seal.write_bytes(seal.read_bytes())
    if use_symlink:
        links = tmp_path / "evidence-links"
        links.mkdir()
        supplied_prediction = links / "predictions.json"
        supplied_seal = links / "predictions.seal.json"
        try:
            os.symlink(gold_prediction, supplied_prediction)
            os.symlink(gold_seal, supplied_seal)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows symlink privilege is unavailable")
            raise
    else:
        supplied_prediction = gold_prediction
        supplied_seal = gold_seal
    reads: list[Path] = []
    requests: list[httpx.Request] = []

    def deny_read(path: Path) -> dict[str, object]:
        reads.append(path)
        raise AssertionError("runner must reject gold before reading any input")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("runner must reject gold before HTTP")

    monkeypatch.setattr(runner, "_load_object", deny_read)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="gold"):
            await runner.run_api_slot(
                slot,
                manifest_path=manifest,
                evidence_path=supplied_prediction,
                evidence_seal_path=supplied_seal,
                output_root=tmp_path / "api-runs",
                settings=_settings(),
                client=client,
            )

    assert reads == []
    assert requests == []
    assert not (tmp_path / "api-runs").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", ["../../outside", "absolute"])
async def test_unsafe_case_id_is_rejected_without_any_read_http_or_artifact_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
) -> None:
    import secmind.reverse_api_runner as runner

    supplied_case_id = str(tmp_path / "outside-absolute") if case_id == "absolute" else case_id
    unsafe_slot = ApiRunSlot(
        arm="current",
        case_id=supplied_case_id,
        repeat_id=1,
        evidence_sha256="a" * 64,
        prompt_sha256="b" * 64,
    )
    reads: list[Path] = []
    requests: list[httpx.Request] = []

    def deny_read(path: Path) -> dict[str, object]:
        reads.append(path)
        raise AssertionError("runner must reject path traversal before reading inputs")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("runner must reject path traversal before HTTP")

    monkeypatch.setattr(runner, "_load_object", deny_read)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="safe path segment"):
            await runner.run_api_slot(
                unsafe_slot,
                manifest_path=tmp_path / "manifest.json",
                evidence_path=tmp_path / "predictions.json",
                evidence_seal_path=tmp_path / "predictions.seal.json",
                output_root=tmp_path / "api-runs",
                settings=_settings(),
                client=client,
            )

    assert reads == []
    assert requests == []
    assert not (tmp_path / "api-runs").exists()
    assert not (tmp_path / "outside").exists()


@pytest.mark.asyncio
async def test_structured_invalid_output_is_retried_until_valid(tmp_path: Path) -> None:
    """A transient malformed answer is retried so the slot still produces a report."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": json.dumps({"bad": "schema"})}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                },
                headers={"x-request-id": "retry-invalid-schema"},
            )
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(evidence_refs=[model_input["allowed_evidence_refs"][0]])
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
            max_output_attempts=3,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert len(requests) == 2
    assert result.report.execution_status == "completed"
    assert receipt["execution_status"] == "completed"
    assert receipt["error_type"] is None
    assert receipt["retry_count"] == 1
    assert receipt["usage"]["provider_requests"] == 2
    assert len(receipt["attempts"]) == 2
    assert receipt["usage"]["total_tokens"] == 240


@pytest.mark.asyncio
async def test_unsafe_model_payload_is_retried_until_safe(tmp_path: Path) -> None:
    """A transient safety rejection is retried so a clean answer can land."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            unsafe_response = _business_response()
            unsafe_response["executive_summary"] = "unsafe test-deepseek-key must not persist"
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": json.dumps(unsafe_response)}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                },
            )
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(evidence_refs=[model_input["allowed_evidence_refs"][0]])
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
            max_output_attempts=3,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    serialized = "".join(path.read_text(encoding="utf-8") for path in result.artifacts.values())
    assert len(requests) == 2
    assert result.report.execution_status == "completed"
    assert receipt["error_type"] is None
    assert receipt["retry_count"] == 1
    assert receipt["usage"]["provider_requests"] == 2
    assert len(receipt["attempts"]) == 2
    assert "test-deepseek-key" not in serialized
    assert "Authorization" not in serialized


@pytest.mark.asyncio
async def test_exhausted_retries_merge_all_attempts_into_unavailable_receipt(tmp_path: Path) -> None:
    """After the retry budget is spent, every paid attempt stays in the receipt."""

    from secmind.reverse_api_runner import run_api_slot

    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        requests.append(_request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({"bad": "schema"})}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            headers={"x-request-id": "always-invalid-schema"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
            max_output_attempts=3,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert len(requests) == 3
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "STRUCTURED_OUTPUT_INVALID"
    assert receipt["retry_count"] == 2
    assert receipt["usage"]["provider_requests"] == 3
    assert len(receipt["attempts"]) == 3
    assert receipt["usage"]["total_tokens"] == 360


@pytest.mark.asyncio
async def test_model_gateway_error_is_retried_until_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient provider transport failure is retried so a real answer lands."""

    import secmind.reverse_api_runner as runner
    from secmind.reverse_api_runner import run_api_slot

    async def no_backoff(_attempt_index: int) -> None:
        return None

    monkeypatch.setattr(runner, "_retry_backoff", no_backoff)
    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) <= 3:
            # Tenacity retries the transport slot three times inside the first
            # structured call; all three answer 503 so the call fails with a
            # MODEL_GATEWAY_ERROR that the runner then retries.
            return httpx.Response(503, json={"error": {"message": "maintenance"}})
        model_input = json.loads(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _business_response(evidence_refs=[model_input["allowed_evidence_refs"][0]])
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
            max_output_attempts=3,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert len(requests) == 4
    assert result.report.execution_status == "completed"
    assert receipt["execution_status"] == "completed"
    assert receipt["error_type"] is None
    assert receipt["retry_count"] == 3
    assert receipt["usage"]["provider_requests"] == 4
    assert len(receipt["attempts"]) == 4


@pytest.mark.asyncio
async def test_model_gateway_error_exhausted_attempts_merge_into_unavailable_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every transport attempt from every runner retry stays in the receipt."""

    import secmind.reverse_api_runner as runner
    from secmind.reverse_api_runner import run_api_slot

    async def no_backoff(_attempt_index: int) -> None:
        return None

    monkeypatch.setattr(runner, "_retry_backoff", no_backoff)
    slot, manifest, evidence, seal = _slot_inputs(tmp_path)
    requests: list[httpx.Request] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        requests.append(_request)
        return httpx.Response(503, json={"error": {"message": "maintenance"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await run_api_slot(
            slot,
            manifest_path=manifest,
            evidence_path=evidence,
            evidence_seal_path=seal,
            output_root=tmp_path / "api-runs",
            settings=_settings(),
            client=client,
            max_output_attempts=3,
        )

    receipt = json.loads(result.artifacts["receipt.json"].read_text(encoding="utf-8"))
    assert len(requests) == 9
    assert result.report.execution_status == "unavailable"
    assert receipt["error_type"] == "MODEL_GATEWAY_ERROR"
    assert receipt["retry_count"] == 8
    assert receipt["usage"]["provider_requests"] == 9
    assert len(receipt["attempts"]) == 9
