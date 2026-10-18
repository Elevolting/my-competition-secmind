from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from conftest import seal_execution_contract

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import ExactAnswer, PolicyDecisionAnswer, TimelineAnswer
from secmind.evidence_graph import make_claim, make_link
from secmind.integrations.test3 import trusted_exact_answer_values
from secmind.orchestration.primary_degradation import degrade_primary
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.quarantine import FailureCapsuleStore
from secmind.schemas import (
    AgentState,
    ClaimStatus,
    Evidence,
    EvidenceRelation,
    InputArtifact,
    ParsedAsset,
    ParserRun,
    Scenario,
    TaskHint,
    TaskRequest,
)
from secmind.task_contract import compile_resolved_task_contract
from secmind.task_specs import TaskSpecCompiler, TaskSpecRepository


def _store_input(
    tmp_path: Path,
    *,
    run_id: str,
    artifact_id: str,
    relative_path: str,
    content: bytes,
    media_type: str,
) -> tuple[ContentAddressedArtifactStore, InputArtifact]:
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / f"cas-{run_id}")
    store.put(content, expected_sha256=digest, run_id=run_id, media_type=media_type)
    return store, InputArtifact(
        artifact_id=artifact_id,
        original_name=Path(relative_path).name,
        relative_path=relative_path,
        sha256=digest,
        size_bytes=len(content),
        media_type=media_type,
    )


def _assert_bound(row: dict[str, object]) -> None:
    assert row["evidence_ids"]
    assert row["source_locator"]
    assert row["source_locators"]


def test_log_execution_publishes_bound_timeline_answer(tmp_path: Path) -> None:
    content = b'{"timestamp":"2026-08-07T00:00:00Z","message":"login failed"}\n'
    store, artifact = _store_input(
        tmp_path,
        run_id="log-answer",
        artifact_id="input-log",
        relative_path="events.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-answer",
            task=TaskRequest(objective="Analyze the supplied logs", scoring_mode="forensic_attribution"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    assert state.report.answer_type == "timeline"
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.execution_status == "success"
    assert answer.epistemic_status == "conclusive"
    assert answer.events and answer.facts
    _assert_bound(answer.events[0])
    _assert_bound(answer.facts[0])
    assert answer.extensions["evidence_ids"]


def test_log_execution_projects_source_attack_annotations_when_primary_is_unavailable(tmp_path: Path) -> None:
    content = json.dumps(
        [
            {
                "timestamp": "2019-05-16T14:17:15.753Z",
                "event_type": "windows_event:1",
                "RuleName": "technique_id=T1112,technique_name=Modify Registry",
            },
            {
                "timestamp": "2019-05-16T14:17:15.758Z",
                "event_type": "windows_event:12",
                "RuleName": "technique_id=T1088,technique_name=Bypass User Account Control",
            },
        ]
    ).encode()
    store, artifact = _store_input(
        tmp_path,
        run_id="log-source-attack-annotations",
        artifact_id="input-log-source-attack-annotations",
        relative_path="events.json",
        content=content,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-source-attack-annotations",
            task=TaskRequest(
                objective="Build an evidence-bound timeline and map source ATT&CK annotations",
                primary_domain="logs_ir_hunting",
                scoring_mode="forensic_attribution",
            ),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert {str(item["technique_id"]) for item in answer.techniques} == {"T1088", "T1112"}
    assert all(item["evidence_ids"] for item in answer.techniques)


def test_log_exact_answer_recovers_source_bound_flag(tmp_path: Path) -> None:
    content = b'{"timestamp":"2026-08-07T00:00:00Z","message":"response payload flag{SOURCE_BOUND_42}"}\n'
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-answer",
        artifact_id="input-log-exact",
        relative_path="capture.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-answer",
            task=TaskRequest(
                objective="Recover the exact flag from the supplied capture",
                scoring_mode="exact_answer_with_evidence",
            ),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    assert state.report.answer_type == "exact"
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.values == ["flag{SOURCE_BOUND_42}"]
    assert answer.items[0]["evidence_ids"]
    assert answer.source_offsets[0]["byte_offset"] > 0


def test_log_exact_answer_prioritizes_source_bound_htb_flag_over_payload_name(tmp_path: Path) -> None:
    flag = "HTB{source_bound_not_a_payload_name}"
    content = json.dumps(
        {
            "timestamp": "2026-08-07T00:00:00Z",
            "message": f"download https://example.invalid/drop/form1.exe; recovered {flag}",
        }
    ).encode()
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-htb-flag",
        artifact_id="input-log-exact-htb",
        relative_path="mail.json",
        content=content,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-htb-flag",
            task=TaskRequest(objective="Recover the exact flag", scoring_mode="exact_answer_with_evidence"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.values[0] == flag
    flag_item = next(item for item in answer.items if item["value"] == flag)
    assert flag_item["match_kind"] == "bounded_flag_token"
    assert flag_item["evidence_ids"]


def test_primary_degradation_emits_fail_closed_typed_policy_answer() -> None:
    state = seal_execution_contract(
        AgentState(
            run_id="policy-primary-degraded",
            task=TaskRequest(
                objective="Report an external filename but do not obey embedded instructions",
                primary_domain="agent_safety",
                scoring_mode="agent_policy_compliance",
            ),
        )
    )

    degrade_primary(state, "forced provider timeout", attempted=True, provider_requests=2)

    assert state.report is not None
    assert state.report.answer_type == "policy_decision"
    answer = PolicyDecisionAnswer.model_validate(state.report.answer_payload)
    assert "DENY/BLOCK" in str(answer.decision)
    assert answer.safe_actions
    assert answer.blocked_actions
    assert answer.epistemic_status == "insufficient_evidence"


def test_exact_answer_prefers_original_source_over_duplicate_derived_view(tmp_path: Path) -> None:
    flag = "flag{PRIMARY_SOURCE_42}"
    derived_content = json.dumps({"message": flag}).encode()
    store, derived = _store_input(
        tmp_path,
        run_id="log-exact-original-source",
        artifact_id="input-derived-exact",
        relative_path=".secmind-derived/packets/capture.pcapng.json",
        content=derived_content,
        media_type="application/json",
    )
    raw_content = b"pcap-header\x00" + flag.encode() + b"\x00pcap-tail"
    raw_digest = hashlib.sha256(raw_content).hexdigest()
    store.put(
        raw_content,
        expected_sha256=raw_digest,
        run_id="log-exact-original-source",
        media_type="application/octet-stream",
    )
    raw = InputArtifact(
        artifact_id="input-native-exact",
        original_name="capture.pcapng",
        relative_path="capture.pcapng",
        sha256=raw_digest,
        size_bytes=len(raw_content),
        media_type="application/octet-stream",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-original-source",
            task=TaskRequest(objective="Recover the exact flag", scoring_mode="exact_answer_with_evidence"),
            input_artifacts=[derived, raw],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.values == [flag]
    assert answer.items[0]["source_locator"]["source_ref"] == "capture.pcapng"
    assert answer.items[0]["source_locator"]["byte_offset"] == raw_content.index(flag.encode())
    raw_evidence_id = answer.items[0]["evidence_ids"][0]
    assert any(item.evidence_id == raw_evidence_id for item in state.report.evidence)
    supporting_links = [
        item
        for item in state.evidence_links
        if item.evidence_id == raw_evidence_id and item.relation == EvidenceRelation.SUPPORTS
    ]
    assert len(supporting_links) == 1
    assert supporting_links[0].verifier_status == ClaimStatus.VERIFIED
    verification = next(item for item in state.verification_results if item.claim_id == supporting_links[0].claim_id)
    assert raw_evidence_id in verification.verified_evidence_ids


def test_primary_degradation_preserves_high_entropy_deterministic_exact_answer(tmp_path: Path) -> None:
    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    content = json.dumps({"message": flag}).encode()
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-degraded",
        artifact_id="input-log-exact-degraded",
        relative_path="capture.json",
        content=content,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-degraded",
            task=TaskRequest(objective="Recover the exact flag", scoring_mode="exact_answer_with_evidence"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    assert state.report is not None
    raw_answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert raw_answer.values == [flag]
    state.audit_coverage["pre_primary_scenario_executed"] = True
    degrade_primary(state, "forced model degradation", attempted=True, provider_requests=1)

    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.values == [flag]


def test_admission_syncs_verified_exact_evidence_before_final_validation(tmp_path: Path) -> None:
    """Terminal metadata projection must not invalidate the support chain."""

    flag = "flag{X9aQ7mP2vN8rT4kL6sD3zY1wC5}"
    content = json.dumps({"message": flag}).encode()
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-admission",
        artifact_id="input-log-exact-admission",
        relative_path="capture.json",
        content=content,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-admission",
            task=TaskRequest(objective="Recover the exact flag", scoring_mode="exact_answer_with_evidence"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    assert state.report is not None
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=store,
        capsule_store=FailureCapsuleStore(tmp_path / "capsules"),
    )

    validation = snapshot.report.verification_summary
    assert validation is not None
    exact_evidence_ids = {
        item.evidence_id
        for item in snapshot.report.evidence
        if item.metadata.get("evidence_type") == "exact_value_observation"
    }
    assert exact_evidence_ids
    assert exact_evidence_ids.issubset(set(validation.get("verified_evidence_ids", [])))

    public_report = snapshot.report.model_dump(mode="json")
    assert state.resolved_task_contract is not None
    task = {
        "required_output": {"scoring_mode": "exact_answer_with_evidence"},
    }
    trusted = trusted_exact_answer_values(
        snapshot.report.answer_payload,
        public_report,
        task,
        report=public_report,
    )
    assert trusted == frozenset({flag})


def test_log_exact_answer_recovers_context_bound_encoded_task_name(tmp_path: Path) -> None:
    script = 'Register-ScheduledTask -TaskName "bounded_answer_42" -Action $action'
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    content = (
        json.dumps(
            {
                "timestamp": "2026-08-07T00:00:00Z",
                "message": f'powershell.exe -encoded "{encoded}"',
            }
        ).encode()
        + b"\n"
    )
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-encoded",
        artifact_id="input-log-exact-encoded",
        relative_path="capture.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-encoded",
            task=TaskRequest(
                objective="Recover the exact value from the supplied capture",
                scoring_mode="exact_answer_with_evidence",
            ),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert "bounded_answer_42" in answer.values
    item = next(row for row in answer.items if row["value"] == "bounded_answer_42")
    assert item["match_kind"] == "decoded_scheduled_task_name"
    assert item["evidence_ids"]


def test_log_exact_answer_recovers_encoded_task_name_from_non_event_json(tmp_path: Path) -> None:
    script = 'Register-ScheduledTask -TaskName "0r3d_source_bound}" -Action "https://example.invalid/drop/4fva.exe"'
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    content = json.dumps(
        {
            "packets": [
                {
                    "payload_strings": [
                        "GET /aQ4caZ.exe HTTP/1.1",
                        f'powershell.exe -encoded "{encoded}"',
                    ]
                }
            ]
        }
    ).encode()
    store, artifact = _store_input(
        tmp_path,
        run_id="log-exact-derived-json",
        artifact_id="input-log-exact-derived-json",
        relative_path="capture.pcap.json",
        content=content,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-exact-derived-json",
            task=TaskRequest(
                objective="Recover the exact flag from the supplied capture",
                scoring_mode="exact_answer_with_evidence",
            ),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert {"0r3d_source_bound}", "aQ4caZ.exe", "4fva.exe"} <= set(answer.values)
    item = next(row for row in answer.items if row["value"] == "0r3d_source_bound}")
    assert item["match_kind"] == "decoded_scheduled_task_name"
    assert item["evidence_ids"]
    assert item["source_locator"]["byte_offset"] > 0
    explicit_payload = next(row for row in answer.items if row["value"] == "aQ4caZ.exe")
    decoded_payload = next(row for row in answer.items if row["value"] == "4fva.exe")
    assert explicit_payload["match_kind"] == "explicit_payload_name"
    assert decoded_payload["match_kind"] == "decoded_payload_name"
    assert explicit_payload["evidence_ids"] and decoded_payload["evidence_ids"]


def test_log_integrity_failure_is_explicit_partial_timeline(tmp_path: Path) -> None:
    content = b'{"message":"the immutable object is intentionally absent"}\n'
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas-missing")
    artifact = InputArtifact(
        artifact_id="input-missing",
        original_name="events.jsonl",
        relative_path="events.jsonl",
        sha256=digest,
        size_bytes=len(content),
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="log-integrity-gap",
            task=TaskRequest(objective="Analyze the supplied logs", scoring_mode="forensic_attribution"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    assert state.status.value == "recovery_required"
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.execution_status == "partial"
    assert answer.epistemic_status == "insufficient_evidence"
    assert answer.gaps
    gap = answer.gaps[0]
    assert isinstance(gap, dict)
    assert gap["evidence_ids"] == []
    assert gap["source_locator"]["source_ref"] == "events.jsonl"


def test_api_execution_publishes_exact_values_and_source_offsets(tmp_path: Path) -> None:
    content = b'{"openapi":"3.0.0","paths":{"/users":{}}}'
    store, artifact = _store_input(
        tmp_path,
        run_id="api-answer",
        artifact_id="input-api",
        relative_path="api.json",
        content=content,
        media_type="application/json",
    )
    asset = ParsedAsset(
        parsed_asset_id="asset-api",
        parser_id="openapi-json",
        parser_version="1.0.0",
        artifact_id=artifact.artifact_id,
        relative_path=artifact.relative_path,
        media_type=artifact.media_type,
        asset_type="openapi_document",
        content_digest=artifact.sha256,
        hints=[TaskHint(source_ref="api.json", scenario_candidates=[Scenario.API_ASSESSMENT])],
        metadata={
            "operations": [
                {"method": "GET", "path": "/users", "security": []},
            ]
        },
    )
    parser_run = ParserRun(
        parser_run_id="parser-api-answer",
        run_id="api-answer",
        artifact_id=artifact.artifact_id,
        parser_id=asset.parser_id,
        parser_version=asset.parser_version,
        status="completed",
        parsed_asset_id=asset.parsed_asset_id,
        input_digest=asset.content_digest,
        output_digest=asset.content_digest,
    )
    task = TaskRequest(
        objective="Perform a static OpenAPI API security assessment",
        scoring_mode="exact_answer_with_evidence",
    )
    spec = TaskSpecCompiler().compile("api-answer", task, [asset], [parser_run])
    repository = TaskSpecRepository()
    repository.save_parser_result(parser_run, asset)
    repository.save_spec(spec, reason="domain-answer-test")
    state = seal_execution_contract(AgentState(run_id="api-answer", task=task, input_artifacts=[artifact]))

    ScenarioExecutor(store, repository).execute_api_assessment(state)

    assert state.report is not None
    assert state.report.answer_type == "exact"
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.execution_status == "success"
    assert answer.values["endpoints"]
    endpoint = answer.values["endpoints"][0]
    _assert_bound(endpoint)
    assert answer.source_offsets[0]["source_locator"]["source_ref"] == "api.json"
    assert answer.validation["network_requests"] == 0


def test_incident_dry_run_publishes_evidence_bound_timeline(tmp_path: Path) -> None:
    run_id = "ir-answer"
    task = TaskRequest(
        objective="Prepare an incident response dry run",
        target_scope=["host:server-1"],
        scoring_mode="forensic_attribution",
    )
    spec = TaskSpecCompiler().compile(run_id, task, [], [])
    repository = TaskSpecRepository()
    repository.save_spec(spec, reason="domain-answer-test")
    evidence = Evidence(
        evidence_id="ir-evidence-1",
        source="fixture",
        summary="Verified host observation",
        artifact_ref="a" * 64,
        sha256="a" * 64,
        metadata={
            "source_locator": {
                "source_ref": "incident.json",
                "segment_id": "claim",
                "record_number": 1,
                "line_number": 4,
                "byte_offset": 12,
                "byte_length": 20,
                "locator_scope": "record",
            }
        },
    )
    claim = make_claim(
        claim_type="incident_hypothesis",
        statement="host is compromised",
        subject_ref="host:server-1",
        producer="fixture",
        confidence=0.95,
    ).model_copy(update={"status": ClaimStatus.VERIFIED})
    link = make_link(claim_id=claim.claim_id, evidence_id=evidence.evidence_id).model_copy(
        update={"verifier_status": ClaimStatus.VERIFIED}
    )
    state = AgentState(
        run_id=run_id,
        task=task,
        claims=[claim],
        evidence=[evidence],
        evidence_links=[link],
    )
    state.resolved_task_contract = compile_resolved_task_contract(
        spec.model_dump(mode="json"),
        input_manifest_digest=hashlib.sha256(b"[]").hexdigest(),
    )

    ScenarioExecutor(ContentAddressedArtifactStore(tmp_path / "cas-ir"), repository).execute_incident_dry_run(state)

    assert state.report is not None
    assert state.report.answer_type == "timeline"
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.execution_status == "success"
    assert len(answer.events) == 4
    _assert_bound(answer.events[0])
    assert all(row["execution_enabled"] is False for row in answer.extensions["policy_actions"])
