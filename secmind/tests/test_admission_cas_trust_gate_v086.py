"""Admission CAS integrity gates for exact-answer trust release."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from conftest import seal_execution_contract

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import ExactAnswer
from secmind.integrations.test3 import trusted_exact_answer_values
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.quarantine import FailureCapsuleStore
from secmind.schemas import AgentState, InputArtifact, SealedAdmissionSnapshot, TaskRequest
from secmind.task_specs import TaskSpecRepository


def _exact_state(tmp_path: Path, run_id: str) -> tuple[AgentState, ContentAddressedArtifactStore]:
    flag = "flag{CAS_REHASH_BOUND_42}"
    content = json.dumps({"message": flag}).encode()
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / f"cas-{run_id}")
    store.put(
        content,
        expected_sha256=digest,
        run_id=run_id,
        media_type="application/json",
    )
    state = seal_execution_contract(
        AgentState(
            run_id=run_id,
            task=TaskRequest(
                objective="Recover the exact flag from the supplied capture",
                scoring_mode="exact_answer_with_evidence",
            ),
            input_artifacts=[
                InputArtifact(
                    artifact_id=f"input-{run_id}",
                    original_name="capture.json",
                    relative_path="capture.json",
                    sha256=digest,
                    size_bytes=len(content),
                    media_type="application/json",
                )
            ],
        )
    )
    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
    assert state.report is not None
    return state, store


def _seal_after_cas_failure(
    state: AgentState,
    store: ContentAddressedArtifactStore,
) -> tuple[object, str]:
    assert state.report is not None
    exact_evidence = next(
        item for item in state.report.evidence if item.metadata.get("evidence_type") == "exact_value_observation"
    )
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=store,
        capsule_store=FailureCapsuleStore(store.root.parent / "capsules"),
    )
    return snapshot, exact_evidence.evidence_id


def _assert_not_trusted(snapshot: object, state: AgentState, evidence_id: str) -> None:
    assert isinstance(snapshot, SealedAdmissionSnapshot)
    report = snapshot.report
    coverage = report.coverage["admission_cas_rehash"]
    assert evidence_id in coverage["failures"]
    assert evidence_id not in coverage["verified_evidence_ids"]
    assert all(
        item.metadata.get("exact_answer_attestation") is None
        for item in report.evidence
        if item.evidence_id == evidence_id
    )
    answer = ExactAnswer.model_validate(report.answer_payload)
    task = {
        "required_output": {"scoring_mode": "exact_answer_with_evidence"},
        "evaluation_metadata": {
            "input_manifest_digest": state.resolved_task_contract.input_manifest_digest
            if state.resolved_task_contract is not None
            else None
        },
    }
    report_obj = report.model_dump(mode="json")
    assert not trusted_exact_answer_values(answer.model_dump(mode="json"), report_obj, task, report=report_obj)


def test_deleted_exact_artifact_cannot_receive_runtime_attestation(tmp_path: Path) -> None:
    state, store = _exact_state(tmp_path, "cas-delete-exact")
    assert state.report is not None
    exact_evidence = next(
        item for item in state.report.evidence if item.metadata.get("evidence_type") == "exact_value_observation"
    )
    assert exact_evidence.artifact_ref is not None
    store.path_for(exact_evidence.artifact_ref).unlink()

    snapshot, evidence_id = _seal_after_cas_failure(state, store)

    _assert_not_trusted(snapshot, state, evidence_id)


def test_tampered_exact_artifact_cannot_receive_runtime_attestation(tmp_path: Path) -> None:
    state, store = _exact_state(tmp_path, "cas-tamper-exact")
    assert state.report is not None
    exact_evidence = next(
        item for item in state.report.evidence if item.metadata.get("evidence_type") == "exact_value_observation"
    )
    assert exact_evidence.artifact_ref is not None
    artifact_path = store.path_for(exact_evidence.artifact_ref)
    original = artifact_path.read_bytes()
    artifact_path.write_bytes(b"x" * len(original))

    snapshot, evidence_id = _seal_after_cas_failure(state, store)

    _assert_not_trusted(snapshot, state, evidence_id)
