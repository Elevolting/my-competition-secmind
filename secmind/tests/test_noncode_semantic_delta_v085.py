from __future__ import annotations

import hashlib
from pathlib import Path

from conftest import seal_execution_contract

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import ExactAnswer, TimelineAnswer, normalize_domain_answer
from secmind.integrations.test3 import project_domain_result
from secmind.orchestration.domain_projection import (
    build_scenario_semantic_delta_receipt,
    build_scenario_semantic_projection,
)
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.orchestrator import SecMindOrchestrator
from secmind.public_coverage import public_coverage_projection
from secmind.schemas import AgentState, InputArtifact, RunStatus, TaskRequest
from secmind.task_specs import TaskSpecRepository


def _input(
    tmp_path: Path,
    *,
    run_id: str,
    relative_path: str,
    content: bytes,
    media_type: str,
) -> tuple[ContentAddressedArtifactStore, InputArtifact]:
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    store.put(content, expected_sha256=digest, run_id=run_id, media_type=media_type)
    return store, InputArtifact(
        artifact_id=f"input-{run_id}",
        original_name=Path(relative_path).name,
        relative_path=relative_path,
        sha256=digest,
        size_bytes=len(content),
        media_type=media_type,
    )


def test_log_semantic_delta_is_replayable_and_anchor_additive(tmp_path: Path) -> None:
    content = b'{"timestamp":"2026-08-17T00:00:00Z","message":"login failed"}\n'
    store, artifact = _input(
        tmp_path,
        run_id="semantic-log",
        relative_path="events.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="semantic-log",
            task=TaskRequest(objective="Analyze the supplied log", scoring_mode="forensic_attribution"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.semantic_output is not None
    assert answer.semantic_delta is not None
    delta = answer.semantic_delta
    assert delta.anchor_preserved is True
    assert delta.evidence_closure.complete is True
    assert delta.evidence_closure.record_locators
    assert delta.raw_artifact_digests
    assert delta.derived_artifact_digests
    assert delta.process_provenance.input_artifact_digests
    assert delta.process_provenance.output_artifact_digests
    event = answer.semantic_output.events[0]
    assert {"event_id", "timestamp", "entities"} <= event.keys()
    assert state.audit_coverage["typed_semantic_deltas"][0]["delta_id"] == delta.delta_id
    receipt = state.audit_coverage["scenario_semantic_delta_receipt"]
    assert receipt == build_scenario_semantic_delta_receipt(delta)
    assert receipt["run_id"] == state.run_id
    assert receipt["delta_id"] == delta.delta_id
    assert receipt["semantic_digest"] == delta.semantic_digest
    assert receipt["process_digest"]
    assert receipt["admission_ready"] is True
    assert receipt["disposition"] == "accepted"

    report = state.report.model_dump(mode="json")
    report["coverage"] = public_coverage_projection(state.audit_coverage)
    projected = project_domain_result(
        {
            "status": "PARTIAL",
            "answer": {},
            "evidence": [item.model_dump(mode="json") for item in state.evidence],
        },
        report,
    )
    assert projected["decision_summary"]["process_receipt"]["runtime_bound"] is True
    assert projected["decision_summary"]["tools"]


def test_reference_closed_delta_is_admission_ready_even_when_run_is_partial(tmp_path: Path) -> None:
    content = b'{"timestamp":"2026-08-17T00:00:00Z","message":"login failed"}\n'
    store, artifact = _input(
        tmp_path,
        run_id="semantic-partial-process",
        relative_path="events.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="semantic-partial-process",
            task=TaskRequest(objective="Analyze the supplied log", scoring_mode="forensic_attribution"),
            input_artifacts=[artifact],
        )
    )
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.semantic_delta is not None
    state.status = RunStatus.PARTIAL

    _output, delta = build_scenario_semantic_projection(
        state,
        answer.model_copy(update={"semantic_output": None, "semantic_delta": None}),
        scenario="log_analysis",
        operation="partial_but_reference_closed",
        evidence_by_id={item.evidence_id: item for item in state.evidence},
    )

    assert delta.evidence_closure.complete is True
    assert delta.disposition == "accepted"
    assert delta.admission_ready is True


def test_disabled_binary_parser_degrades_to_typed_evidence_gap(tmp_path: Path) -> None:
    content = b"not an enabled binary parser fixture"
    store, artifact = _input(
        tmp_path,
        run_id="semantic-no-tool",
        relative_path="capture.evtx",
        content=content,
        media_type="application/octet-stream",
    )
    state = seal_execution_contract(
        AgentState(
            run_id="semantic-no-tool",
            task=TaskRequest(objective="Analyze the supplied event log", scoring_mode="forensic_attribution"),
            input_artifacts=[artifact],
        )
    )

    ScenarioExecutor(store, TaskSpecRepository(), binary_log_parsers_enabled=False).execute_log_analysis(state)

    assert state.report is not None
    assert state.status.value == "partial"
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert answer.semantic_delta is not None
    assert answer.semantic_delta.disposition == "quarantined"
    assert answer.semantic_delta.evidence_closure.complete is False
    assert "evidence_ids" in answer.semantic_delta.evidence_closure.missing
    assert artifact.sha256 in answer.semantic_delta.process_provenance.input_artifact_digests
    assert answer.semantic_output is not None
    assert any("parser_unavailable" in item for item in answer.semantic_output.unknowns)


def test_exact_projection_keeps_exact_values_in_shared_fact_lane() -> None:
    answer = ExactAnswer.model_validate(
        {
            "task_id": "exact-projection",
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "values": ["flag{typed_delta}"],
        }
    )
    output, delta = build_scenario_semantic_projection(
        AgentState(run_id="exact-projection", task=TaskRequest(objective="project exact answer")),
        answer,
        scenario="log_analysis",
        operation="exact_projection_test",
    )

    assert output.facts
    assert any(row.get("value") == ["flag{typed_delta}"] for row in output.facts)
    assert any(row.get("value") == ["flag{typed_delta}"] for row in delta.facts)


def test_pre_primary_domain_projection_survives_active_answer_fusion() -> None:
    """Parser graphs and provenance must not disappear at Primary publication."""

    state = AgentState(
        run_id="fusion-domain",
        task=TaskRequest(objective="inspect supplied incident records", scoring_mode="forensic_attribution"),
    )
    locator = {
        "source_ref": "events.jsonl",
        "segment_id": "record-1",
        "record_number": 1,
        "line_number": 1,
        "byte_offset": 0,
        "byte_length": 32,
        "locator_scope": "record",
        "artifact_sha256": "a" * 64,
    }
    parser_answer = TimelineAnswer.model_validate(
        {
            "task_id": state.run_id,
            "execution_status": "success",
            "epistemic_status": "conclusive",
            "events": [
                {
                    "event_id": "parser-event-1",
                    "event_type": "incident_dry_run_action",
                    "timestamp": "2026-08-17T00:00:00Z",
                    "evidence_ids": ["evidence-1"],
                    "source_locator": locator,
                }
            ],
            "extensions": {
                "policy_actions": [
                    {
                        "action_id": "contain-1",
                        "phase": "containment",
                        "title": "Prepare isolation",
                        "subject_ref": "host:one",
                        "policy_action": "require_approval",
                        "execution_enabled": False,
                        "expected_impact": "service interruption after approval",
                        "rollback_condition": "host differs from evidence",
                        "evidence_ids": ["evidence-1"],
                        "source_locator": locator,
                    }
                ],
                "hypotheses": [
                    {
                        "hypothesis_id": "hypothesis-1",
                        "statement": "The host may be compromised.",
                        "subject_ref": "host:one",
                        "status": "unverified",
                        "evidence_ids": ["evidence-1"],
                        "source_locator": locator,
                    }
                ],
                "process_provenance": {"process_id": "parser", "process_version": "1"},
            },
        }
    )
    output, delta = build_scenario_semantic_projection(
        state,
        parser_answer,
        scenario="incident_response",
        operation="fixture-parser",
        evidence_by_id={},
    )
    parser_answer = parser_answer.model_copy(update={"semantic_output": output, "semantic_delta": delta})
    assert output is not None
    state.audit_coverage["pre_primary_scenario_projection"] = {
        "scenario": "incident_response",
        "answer_payload": parser_answer.model_dump(mode="json"),
    }
    provider_answer = normalize_domain_answer(
        "forensic_attribution",
        {
            "task_id": state.run_id,
            "status": "completed",
            "facts": [],
            "events": [],
        },
    )

    fused = SecMindOrchestrator._fuse_pre_primary_scenario_answer(state, provider_answer)

    assert isinstance(fused, TimelineAnswer)
    assert fused.events[0]["event_id"] == "parser-event-1"
    assert fused.semantic_output is not None
    assert fused.semantic_output.process_provenance.process_id == output.process_provenance.process_id
    assert fused.semantic_delta is not None
    assert fused.semantic_delta.process_provenance.output_artifact_digests
    assert fused.extensions["policy_actions"][0]["action_id"] == "contain-1"
    assert fused.incident_response is not None
    assert fused.incident_response.actions[0].action_id == "contain-1"
    assert fused.incident_response.hypotheses[0].hypothesis_id == "hypothesis-1"
    assert fused.semantic_output is not None
    assert fused.semantic_output.incident_response is not None
    assert fused.semantic_output.incident_response.hypotheses[0].hypothesis_id == "hypothesis-1"
