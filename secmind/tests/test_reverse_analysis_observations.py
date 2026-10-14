from __future__ import annotations

import hashlib
from pathlib import Path

from conftest import seal_execution_contract

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import ReverseBehaviorAnswer
from secmind.guardrail import Guardrail
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.schemas import AgentState, Evidence, InputArtifact, Scenario, TaskRequest, ToolResult, ToolStatus
from secmind.task_specs import TaskSpecRepository
from secmind.tooling.builtin_reverse_pe import ReversePeAnalysisTool
from secmind.tools import ToolBroker, default_registry


def _sample() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "reverse_evaluation"
        / "fixtures"
        / "safe-demo-v1"
        / "build"
        / "reverse_demo.exe"
    )


def test_pe_tool_declares_reverse_triage_scenario() -> None:
    assert ReversePeAnalysisTool.manifest.scenarios == [Scenario.REVERSE_TRIAGE]


def test_xor_true_values_rank_ahead_of_padding_noise() -> None:
    from secmind.reverse_pe_analysis import build_report

    report = build_report(_sample())
    candidates = report["xor_decode_candidates"]
    values = [item["value"] for item in candidates]

    assert "SECMIND-REVERSE-OK" in values[:5]
    assert "training.example.invalid" in values[:5]
    assert all(not value.startswith(("ZZZZ", "AAAA", "XXXX")) for value in values[:5])
    assert all(item["confidence"] in {"high", "medium"} for item in candidates)


def test_import_hints_are_static_presence_not_runtime_calls() -> None:
    from secmind.reverse_pe_analysis import build_report

    report = build_report(_sample())

    assert report["import_semantics"] == "static_presence"
    assert report["runtime_calls_observed"] is False
    assert all(item["observation"] == "static_presence" for item in report["import_hints"])


def test_fact_fusion_preserves_static_dynamic_and_conflicts() -> None:
    from secmind.reverse_analysis_observation import fuse_reverse_facts

    fused = fuse_reverse_facts(
        {
            "static": {"value": "PE", "evidence_refs": ["s-1"]},
            "same": {"value": 2, "evidence_refs": ["s-2"]},
            "conflict": {"value": "x86", "evidence_refs": ["s-3"]},
        },
        {
            "dynamic": {"value": "fopen", "evidence_refs": ["d-1"]},
            "same": {"value": 2, "evidence_refs": ["d-2"]},
            "conflict": {"value": "x64", "evidence_refs": ["d-3"]},
        },
    )

    assert fused["static"]["provenance"] == "static_only"
    assert fused["dynamic"]["provenance"] == "dynamic_only"
    assert fused["same"]["provenance"] == "observed_runtime"
    assert fused["conflict"] == {
        "value": {"static": "x86", "dynamic": "x64"},
        "provenance": "conflict",
        "evidence_refs": ["s-3", "d-3"],
    }


def test_agent_projects_static_pe_facts_into_reverse_analysis_extension(tmp_path: Path) -> None:
    sample = _sample()
    raw = sample.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    copied = tmp_path / sample.name
    copied.write_bytes(raw)
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    store.put(raw, expected_sha256=digest, run_id="projection", media_type="application/x-msdownload")
    state = seal_execution_contract(
        AgentState(
            run_id="projection",
            task=TaskRequest(
                objective="reverse safe sample",
                primary_domain="forensics_static_reverse",
                scoring_mode="reverse_behavior",
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            workspace=str(tmp_path),
            input_artifacts=[
                InputArtifact(
                    artifact_id="sample",
                    original_name=sample.name,
                    relative_path=sample.name,
                    sha256=digest,
                    size_bytes=len(raw),
                    media_type="application/x-msdownload",
                )
            ],
        )
    )

    ScenarioExecutor(
        store, TaskSpecRepository(), broker=ToolBroker(default_registry(), Guardrail())
    ).execute_reverse_triage(state)

    assert state.report is not None
    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    reverse = answer.extensions["reverse_analysis"]
    observation = reverse["observations"][0]
    assert observation["source"] == "static_pe"
    assert observation["sample_sha256"] == digest
    assert observation["coverage"]["architecture"] == "x86-64"
    assert "strcmp" in observation["artifacts"]["imports"]
    assert observation["events"] == []
    assert reverse["fused_facts"]["format"]["provenance"] == "static_only"
    assert state.report.evidence
    pe_evidence = state.report.evidence[0]
    assert pe_evidence.artifact_ref == digest
    assert pe_evidence.sha256 == digest
    assert any(
        link.evidence_id == pe_evidence.evidence_id and link.verifier_status.value == "verified"
        for link in state.evidence_links
    )


def test_agent_fuses_two_dynamic_profiles_without_losing_static_observation(tmp_path: Path) -> None:
    from secmind.reverse_pe_analysis import build_report

    sample = _sample()
    raw = sample.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / sample.name).write_bytes(raw)
    store = ContentAddressedArtifactStore(tmp_path / "cas-dynamic")
    store.put(raw, expected_sha256=digest, run_id="dynamic-fusion", media_type="application/x-msdownload")
    state = seal_execution_contract(
        AgentState(
            run_id="dynamic-fusion",
            task=TaskRequest(
                objective="dynamic reverse", primary_domain="forensics_static_reverse", scoring_mode="reverse_behavior"
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            workspace=str(tmp_path),
            input_artifacts=[
                InputArtifact(
                    artifact_id="sample",
                    original_name=sample.name,
                    relative_path=sample.name,
                    sha256=digest,
                    size_bytes=len(raw),
                    media_type="application/x-msdownload",
                )
            ],
        )
    )

    class Broker:
        async def execute(self, name, args, _context, **_kwargs):
            if name == "pe_reverse_analysis":
                return ToolResult(status=ToolStatus.SUCCESS, data=build_report(tmp_path / sample.name))
            exit_code = 2 if args["profile_id"] == "wrong_token" else 0
            created = [] if exit_code else ["reverse_demo_result.txt"]
            return ToolResult(
                status=ToolStatus.SUCCESS,
                evidence=[
                    Evidence(
                        evidence_id="mismatched-dynamic-evidence",
                        source="test",
                        summary="must not enter the trusted ledger",
                        sha256="c" * 64,
                    )
                ],
                data={
                    "source": "speakeasy",
                    "status": "completed",
                    "sample_sha256": digest,
                    "tool_identity": {"name": "speakeasy", "version": "2.0.0b6"},
                    "profile_id": args["profile_id"],
                    "coverage": {"real_network_requests": 0, "host_pe_executions": 0},
                    "events": [],
                    "artifacts": {"exit_code": exit_code, "created_files": created},
                    "evidence_refs": [],
                    "error": None,
                },
            )

    ScenarioExecutor(store, TaskSpecRepository(), broker=Broker(), reverse_dynamic_enabled=True).execute_reverse_triage(
        state
    )

    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    observations = answer.extensions["reverse_analysis"]["observations"]
    assert [item["source"] for item in observations] == ["static_pe", "speakeasy", "speakeasy"]
    assert {item["profile_id"] for item in observations[1:]} == {"wrong_token", "correct_token"}
    assert answer.extensions["emulation_performed"] is True
    assert answer.extensions["reverse_analysis"]["fused_facts"]["profile:correct_token"]["provenance"] == "dynamic_only"


def test_agent_rejects_dynamic_observation_bound_to_another_sample(tmp_path: Path) -> None:
    from secmind.reverse_pe_analysis import build_report

    sample = _sample()
    raw = sample.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / sample.name).write_bytes(raw)
    store = ContentAddressedArtifactStore(tmp_path / "cas-hash-mismatch")
    store.put(raw, expected_sha256=digest, run_id="hash-mismatch", media_type="application/x-msdownload")
    state = seal_execution_contract(
        AgentState(
            run_id="hash-mismatch",
            task=TaskRequest(
                objective="dynamic reverse", primary_domain="forensics_static_reverse", scoring_mode="reverse_behavior"
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            workspace=str(tmp_path),
            input_artifacts=[
                InputArtifact(
                    artifact_id="sample",
                    original_name=sample.name,
                    relative_path=sample.name,
                    sha256=digest,
                    size_bytes=len(raw),
                    media_type="application/x-msdownload",
                )
            ],
        )
    )

    class Broker:
        async def execute(self, name, args, _context, **_kwargs):
            if name == "pe_reverse_analysis":
                return ToolResult(status=ToolStatus.SUCCESS, data=build_report(tmp_path / sample.name))
            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "source": "speakeasy",
                    "status": "completed",
                    "sample_sha256": "b" * 64,
                    "tool_identity": {"name": "speakeasy", "version": "2.0.0b6"},
                    "profile_id": args["profile_id"],
                    "coverage": {"real_network_requests": 0, "host_pe_executions": 0},
                    "events": [],
                    "artifacts": {},
                    "evidence_refs": [],
                    "error": None,
                },
            )

    ScenarioExecutor(store, TaskSpecRepository(), broker=Broker(), reverse_dynamic_enabled=True).execute_reverse_triage(
        state
    )

    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    dynamic = answer.extensions["reverse_analysis"]["observations"][1:]
    assert all(item["status"] == "unavailable" for item in dynamic)
    assert all(item["error"]["code"] == "SPEAKEASY_SAMPLE_HASH_MISMATCH" for item in dynamic)
    assert answer.extensions["emulation_performed"] is False
    assert all(item.evidence_id != "mismatched-dynamic-evidence" for item in state.evidence)


def test_dynamic_failure_degrades_to_partial_and_preserves_static(tmp_path: Path) -> None:
    from secmind.reverse_pe_analysis import build_report

    sample = _sample()
    raw = sample.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / sample.name).write_bytes(raw)
    store = ContentAddressedArtifactStore(tmp_path / "cas-failure")
    store.put(raw, expected_sha256=digest, run_id="dynamic-failure", media_type="application/x-msdownload")
    state = seal_execution_contract(
        AgentState(
            run_id="dynamic-failure",
            task=TaskRequest(
                objective="dynamic failure", primary_domain="forensics_static_reverse", scoring_mode="reverse_behavior"
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            workspace=str(tmp_path),
            input_artifacts=[
                InputArtifact(
                    artifact_id="sample",
                    original_name=sample.name,
                    relative_path=sample.name,
                    sha256=digest,
                    size_bytes=len(raw),
                    media_type="application/x-msdownload",
                )
            ],
        )
    )

    class Broker:
        async def execute(self, name, _args, _context, **_kwargs):
            if name == "pe_reverse_analysis":
                return ToolResult(status=ToolStatus.SUCCESS, data=build_report(tmp_path / sample.name))
            return ToolResult(
                status=ToolStatus.ERROR, error_code="SPEAKEASY_UNAVAILABLE", error_message="not installed"
            )

    ScenarioExecutor(store, TaskSpecRepository(), broker=Broker(), reverse_dynamic_enabled=True).execute_reverse_triage(
        state
    )

    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    observations = answer.extensions["reverse_analysis"]["observations"]
    assert state.status.value == "partial"
    assert observations[0]["source"] == "static_pe"
    assert any(item["source"] == "speakeasy" and item["status"] == "unavailable" for item in observations)
    assert answer.extensions["emulation_performed"] is False
