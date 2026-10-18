from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import seal_execution_contract

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import EvidenceGapAnswer, ExactAnswer, TimelineAnswer
from secmind.investigation.contracts import ObligationStatus as InvestigationObligationStatus
from secmind.investigation.contracts import RequirementObligation, seal_contract
from secmind.log_analysis import AttackMapping, merge_attack_mappings
from secmind.orchestration.evidence_compiler_runtime import compile_evidence
from secmind.orchestration.evidence_projection import (
    canonical_primary_baseline_required,
    deterministic_scenario_primary_skip_diagnostics,
    deterministic_scenario_primary_skip_ready,
)
from secmind.orchestration.obligation_runtime import (
    current_obligation_set,
    merge_investigation_obligations,
)
from secmind.orchestration.primary_runtime import (
    checkpoint_deterministic_primary_skip,
    primary_advisory_context,
    record_pre_primary_scenario_result,
)
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.schemas import AgentState, ClaimStatus, InputArtifact, RunStatus, Scenario, TaskRequest
from secmind.task_contract import canonical_digest, resolved_contract_digest
from secmind.task_specs import TaskSpecRepository

_FIXTURES = Path(__file__).parent / "fixtures" / "noncode_v086"


def _add_input(
    store: ContentAddressedArtifactStore,
    *,
    run_id: str,
    relative_path: str,
    content: bytes,
    media_type: str = "application/json",
) -> InputArtifact:
    digest = hashlib.sha256(content).hexdigest()
    store.put(content, expected_sha256=digest, run_id=run_id, media_type=media_type)
    return InputArtifact(
        artifact_id="input-" + hashlib.sha256(f"{run_id}:{relative_path}".encode()).hexdigest()[:24],
        original_name=Path(relative_path).name,
        relative_path=relative_path,
        sha256=digest,
        size_bytes=len(content),
        media_type=media_type,
    )


def _log_state(run_id: str, artifacts: list[InputArtifact]) -> AgentState:
    return _seal_production_contract(
        AgentState(
            run_id=run_id,
            scenario=Scenario.LOG_ANALYSIS,
            task=TaskRequest(
                objective="Read-only forensic timeline and ATT&CK analysis",
                primary_domain="logs_ir_hunting",
                scoring_mode="forensic_attribution",
                interaction_mode="unattended",
            ),
            input_artifacts=artifacts,
        )
    )


def _exact_log_state(run_id: str, artifacts: list[InputArtifact]) -> AgentState:
    return _seal_production_contract(
        AgentState(
            run_id=run_id,
            scenario=Scenario.LOG_ANALYSIS,
            task=TaskRequest(
                client_request_id="eval-" + hashlib.sha256(run_id.encode()).hexdigest()[:32],
                objective="Recover the exact source-bound value",
                primary_domain="complex_input_understanding",
                scoring_mode="exact_answer_with_evidence",
                interaction_mode="unattended",
            ),
            input_artifacts=artifacts,
        )
    )


def _seal_production_contract(state: AgentState) -> AgentState:
    state = seal_execution_contract(state)
    assert state.resolved_task_contract is not None
    payload = state.resolved_task_contract.model_dump(mode="json", exclude={"contract_digest"})
    payload["input_manifest_digest"] = canonical_digest(
        [
            {
                "artifact_id": item.artifact_id,
                "relative_path": item.relative_path,
                "sha256": item.sha256.lower(),
                "size_bytes": item.size_bytes,
                "media_type": item.media_type,
            }
            for item in sorted(state.input_artifacts, key=lambda row: row.relative_path.casefold())
        ]
    )
    payload["contract_digest"] = resolved_contract_digest(payload)
    state.resolved_task_contract = type(state.resolved_task_contract).model_validate(payload)
    return state


def _execute_log(tmp_path: Path, run_id: str, content: bytes) -> AgentState:
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    artifact = _add_input(store, run_id=run_id, relative_path="events.json", content=content)
    state = _log_state(run_id, [artifact])
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    record_pre_primary_scenario_result(state)
    return state


def test_timeline_tactics_are_additive_for_legacy_payloads() -> None:
    answer = TimelineAnswer.model_validate(
        {
            "task_id": "legacy-timeline",
            "execution_status": "partial",
            "epistemic_status": "insufficient_evidence",
            "facts": ["legacy fact"],
            "limitations": ["legacy payload has no tactic field"],
        }
    )

    assert answer.tactics == []


def test_attack_mapping_merge_is_order_independent_and_provenance_bounded() -> None:
    left = AttackMapping(
        "T1021.001", "Remote Desktop Protocol", "v1", ("event-b",), ("rule-b",), 0.4, source_refs=("b.json",)
    )
    right = AttackMapping("T1021.001", "Alternate label", "v1", ("event-a",), ("rule-a",), 0.8, source_refs=("a.json",))

    assert merge_attack_mappings((left,), (right,)) == merge_attack_mappings((right,), (left,))
    merged = merge_attack_mappings((left,), (right,))[0]
    assert merged.event_ids == ("event-a", "event-b")
    assert merged.source_refs == ("a.json", "b.json")


def test_ac6_winrm_chain_materializes_tactics_claim_closure_and_skip(tmp_path: Path) -> None:
    state = _execute_log(tmp_path, "T3S-AC6DD13A9F", (_FIXTURES / "ac6dd13a9f-events.json").read_bytes())

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    techniques = {str(item["technique_id"]) for item in answer.techniques if isinstance(item, dict)}
    assert {"T1021.006", "T1059.003", "T1033"} <= techniques
    assert "T1068" not in techniques
    tactics = {item.tactic_id: item for item in answer.tactics}
    assert {"TA0002", "TA0004", "TA0007", "TA0008"} <= set(tactics)
    assert "mechanism is unknown" in " ".join(tactics["TA0004"].limitations)

    mapping_claims = {
        item.subject_ref.removeprefix("attack-mapping:"): item.claim_id
        for item in state.claims
        if item.claim_type == "attack_mapping_supported" and item.status == ClaimStatus.VERIFIED
    }
    verified_links = {
        (item.claim_id, item.evidence_id)
        for item in state.evidence_links
        if item.verifier_status == ClaimStatus.VERIFIED
    }
    for item in answer.techniques:
        if not isinstance(item, dict):
            continue
        technique_id = str(item["technique_id"])
        assert all(
            (mapping_claims[technique_id], evidence_id) in verified_links for evidence_id in item["evidence_ids"]
        )

    metrics = state.audit_coverage["log_attack_mapping_pipeline"]
    assert metrics["candidate_count"] == metrics["correlated_count"] == 3
    assert metrics["verified_count"] == metrics["admitted_count"] == 3
    assert metrics["evidence_closure_complete"] is True
    assert deterministic_scenario_primary_skip_ready(state) is True
    assert canonical_primary_baseline_required(state) is False


def test_47_rdp_events_remain_low_confidence_context(tmp_path: Path) -> None:
    state = _execute_log(tmp_path, "T3S-47F7E9A537", (_FIXTURES / "47f7e9a537-events.json").read_bytes())

    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert len(answer.tactics) == 1
    tactic = answer.tactics[0]
    assert tactic.tactic_id == "TA0008"
    assert tactic.technique_ids == ["T1021.001"]
    assert tactic.interpretation == "low_confidence_context"
    assert tactic.confidence <= 0.5
    caveat = " ".join(tactic.limitations).casefold()
    assert "does not prove malicious activity" in caveat
    assert "successful remote session" in caveat
    assert deterministic_scenario_primary_skip_ready(state) is True


def test_multi_source_mappings_merge_provenance_and_alternate_failure_cannot_degrade(tmp_path: Path) -> None:
    run_id = "log-multi-source"
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    rdp = (_FIXTURES / "47f7e9a537-events.json").read_bytes()
    native = _add_input(store, run_id=run_id, relative_path="events.json", content=rdp)
    alternate = _add_input(store, run_id=run_id, relative_path=".secmind-derived/events.json.json", content=rdp)
    context = _add_input(store, run_id=run_id, relative_path="README.md", content=b"not a log")
    state = _log_state(run_id, [native, alternate, context])

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    record_pre_primary_scenario_result(state)

    roles = {item["path"]: item["role"] for item in state.audit_coverage["log_input_roles"]}
    assert roles == {
        ".secmind-derived/events.json.json": "alternate",
        "README.md": "context",
        "events.json": "authoritative",
    }
    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = TimelineAnswer.model_validate(state.report.answer_payload)
    assert len(answer.techniques) == 1
    technique = answer.techniques[0]
    assert isinstance(technique, dict)
    assert technique["source_refs"] == [".secmind-derived/events.json.json", "events.json"]
    metrics = state.audit_coverage["log_attack_mapping_pipeline"]
    assert metrics["candidate_count"] == 2
    assert metrics["correlated_count"] == metrics["verified_count"] == metrics["admitted_count"] == 1

    broken = _add_input(
        store,
        run_id=run_id + "-broken",
        relative_path=".secmind-derived/events.json.json",
        content=b"[{broken]",
    )
    native_broken_run = _add_input(
        store,
        run_id=run_id + "-broken",
        relative_path="events.json",
        content=rdp,
    )
    broken_state = _log_state(run_id + "-broken", [native_broken_run, broken])
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(broken_state)
    assert broken_state.status == RunStatus.COMPLETED
    assert broken_state.audit_coverage["log_non_authoritative_diagnostics"]


@pytest.mark.asyncio
async def test_lfs_gap_reuses_semantic_receipt_for_primary_skip_and_fails_closed(tmp_path: Path) -> None:
    run_id = "T3S-LFS-EVIDENCE-GAP"
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    artifact = _add_input(
        store,
        run_id=run_id,
        relative_path="missing-object.json",
        content=(_FIXTURES / "missing-object.json").read_bytes(),
        media_type="application/octet-stream",
    )
    state = _seal_production_contract(
        AgentState(
            run_id=run_id,
            task=TaskRequest(
                objective="State what can and cannot be concluded from the missing LFS object",
                primary_domain="orchestration_recovery_uncertainty",
                scoring_mode="evidence_gap",
                interaction_mode="unattended",
            ),
            input_artifacts=[artifact],
        )
    )
    checkpoints: list[str] = []

    async def checkpoint(current: AgentState, event: str, _payload: Any, *_args: Any) -> AgentState:
        checkpoints.append(event)
        return current

    host = SimpleNamespace(
        _state=lambda _value: state,
        _checkpoint=checkpoint,
        artifact_store=store,
        task_spec_repository=SimpleNamespace(parsed_assets=lambda _run: [], parser_runs=lambda _run: []),
        settings=SimpleNamespace(primary_advisory_context_bytes=4_096),
    )
    await compile_evidence(host, {})

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = EvidenceGapAnswer.model_validate(state.report.answer_payload)
    observation = answer.observations[0]
    assert isinstance(observation, dict)
    assert observation["underlying_object_present"] is False
    assert answer.blocked_claims and answer.next_evidence
    assert state.audit_coverage["pre_primary_scenario_projection"]["scenario"] == "evidence_gap"
    assert deterministic_scenario_primary_skip_ready(state) is True
    await checkpoint_deterministic_primary_skip(host, state)
    assert checkpoints[-1] == "canonical_primary.skipped_deterministic_scenario"
    assert state.audit_coverage["canonical_primary_provider_requests"] == 0

    state.evidence_links[0] = state.evidence_links[0].model_copy(update={"verifier_status": ClaimStatus.CANDIDATE})
    assert deterministic_scenario_primary_skip_ready(state) is False
    assert canonical_primary_baseline_required(state) is True
    advisory = primary_advisory_context(host, state)
    assert [item["kind"] for item in advisory] == ["unresolved_scenario_gap"]
    capsule = json.loads(advisory[0]["content"])
    assert capsule["instruction"].startswith("Resolve only listed gaps")


@pytest.mark.asyncio
async def test_partial_exact_answer_skips_primary_without_promoting_run_status(tmp_path: Path) -> None:
    run_id = "T3S-93F-SHAPED-EXACT"
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    # A valid exact record plus one malformed JSONL record mirrors 93F's
    # source-bound answer with an unrelated parser-coverage limitation.
    content = b'{"message":"FLAG{bounded-exact-value}"}\n{broken-json\n'
    artifact = _add_input(
        store,
        run_id=run_id,
        relative_path="capture.jsonl",
        content=content,
        media_type="application/x-ndjson",
    )
    state = _exact_log_state(run_id, [artifact])
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    record_pre_primary_scenario_result(state)

    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    answer = ExactAnswer.model_validate(state.report.answer_payload)
    assert answer.values == ["FLAG{bounded-exact-value}"]
    answer_set = current_obligation_set(state)
    assert answer_set is not None and answer_set.complete
    unresolved_primary = seal_contract(
        RequirementObligation,
        obligation_id="canonical-primary-baseline-unverified",
        run_id=run_id,
        source_type="canonical_primary_baseline",
        source_ref="canonical-primary",
        requirement_summary="canonical Primary was not invoked",
        immutable_scope=[artifact.relative_path],
        satisfaction_rule_id="canonical-primary-v1",
        required_evidence_types=["canonical_primary_baseline"],
        status=InvestigationObligationStatus.UNVERIFIED,
    )
    merged = merge_investigation_obligations(state, answer_set, [unresolved_primary])
    assert merged.complete is False
    assert deterministic_scenario_primary_skip_ready(state) is True
    assert canonical_primary_baseline_required(state) is False

    checkpoints: list[tuple[str, dict[str, Any]]] = []

    async def checkpoint(current: AgentState, event: str, payload: dict[str, Any]) -> AgentState:
        checkpoints.append((event, payload))
        return current

    await checkpoint_deterministic_primary_skip(SimpleNamespace(_checkpoint=checkpoint), state)
    assert state.status == RunStatus.PARTIAL
    assert state.audit_coverage["canonical_primary_provider_requests"] == 0
    diagnostics = state.audit_coverage["deterministic_primary_skip_diagnostics"]
    assert diagnostics["eligible"] is True
    assert diagnostics["failed_count"] == 0
    assert checkpoints[-1][1]["skip_scope"] == "exact_contract"
    assert checkpoints[-1][1]["preserved_run_status"] == "partial"


def test_partial_exact_primary_skip_fails_closed_on_security_or_binding_errors(tmp_path: Path) -> None:
    run_id = "partial-exact-negative"
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    artifact = _add_input(
        store,
        run_id=run_id,
        relative_path="capture.jsonl",
        content=b'{"message":"FLAG{verified}"}\n{broken-json\n',
        media_type="application/x-ndjson",
    )
    state = _exact_log_state(run_id, [artifact])
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    record_pre_primary_scenario_result(state)
    assert deterministic_scenario_primary_skip_ready(state) is True

    bad_status = state.model_copy(deep=True)
    bad_status.status = RunStatus.RECOVERY_REQUIRED
    assert deterministic_scenario_primary_skip_ready(bad_status) is False

    bad_link = state.model_copy(deep=True)
    exact_claim_ids = {item.claim_id for item in bad_link.claims if item.claim_type == "exact_value_observed"}
    link_index = next(i for i, item in enumerate(bad_link.evidence_links) if item.claim_id in exact_claim_ids)
    bad_link.evidence_links[link_index] = bad_link.evidence_links[link_index].model_copy(
        update={"verifier_status": ClaimStatus.CANDIDATE}
    )
    assert deterministic_scenario_primary_skip_ready(bad_link) is False

    bad_manifest = state.model_copy(deep=True)
    bad_manifest.input_artifacts[0] = bad_manifest.input_artifacts[0].model_copy(update={"sha256": "f" * 64})
    assert deterministic_scenario_primary_skip_ready(bad_manifest) is False

    bad_authorization = state.model_copy(deep=True)
    bad_authorization.last_error = "authorization failed"
    assert deterministic_scenario_primary_skip_ready(bad_authorization) is False
    diagnostics = deterministic_scenario_primary_skip_diagnostics(bad_authorization)
    assert diagnostics["eligible"] is False
    assert diagnostics["reason_codes"] == ["exact.no_last_error"]
    # Diagnostics may reveal gate names and booleans, never task content,
    # evidence values, source paths, or content digests.
    serialized = json.dumps(diagnostics, sort_keys=True)
    assert "FLAG{verified}" not in serialized
    assert artifact.relative_path not in serialized
    assert artifact.sha256 not in serialized


@pytest.mark.asyncio
async def test_primary_skip_failure_is_persisted_as_value_free_diagnostics(tmp_path: Path) -> None:
    run_id = "exact-skip-diagnostics"
    store = ContentAddressedArtifactStore(tmp_path / "cas")
    artifact = _add_input(
        store,
        run_id=run_id,
        relative_path="private-capture.jsonl",
        content=b'{"message":"FLAG{private-value}"}\n{broken-json\n',
        media_type="application/x-ndjson",
    )
    state = _exact_log_state(run_id, [artifact])
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    record_pre_primary_scenario_result(state)
    state.last_error = "authorization failed for private subject"

    await checkpoint_deterministic_primary_skip(SimpleNamespace(_checkpoint=None), state)

    diagnostics = state.audit_coverage["deterministic_primary_skip_diagnostics"]
    assert diagnostics["eligible"] is False
    assert diagnostics["reason_codes"] == ["exact.no_last_error"]
    assert state.report is not None
    assert state.report.coverage["deterministic_primary_skip_diagnostics"] == diagnostics
    serialized = json.dumps(diagnostics, sort_keys=True)
    assert "FLAG{private-value}" not in serialized
    assert "private-capture" not in serialized
    assert artifact.sha256 not in serialized
