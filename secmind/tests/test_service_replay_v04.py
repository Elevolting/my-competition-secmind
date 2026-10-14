from __future__ import annotations

import io
import json
import tempfile
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.coordinator import (
    ArtifactObjectRow,
    CoordinatorStore,
    ModelInvocationRow,
    StepRunRow,
)
from secmind.execution import ApprovalRow, ToolInvocationRow
from secmind.ledger import LedgerStore, canonical_json
from secmind.quarantine import FailureCapsuleStore
from secmind.replay import REQUIRED_REPLAY_ENTRIES, ReplayError
from secmind.schemas import AgentReport, AgentState, InputArtifact, RunStatus, TaskRequest
from secmind.service import EventHub, RunService
from secmind.unit_of_work import CognitiveBase

FIXED_TIME = datetime(2026, 7, 13, 8, 0, tzinfo=UTC)
SECRET = "super-secret-value"  # noqa: S105 - synthetic redaction fixture


@pytest.fixture
def replay_service(tmp_path) -> Iterator[RunService]:
    database_url = f"sqlite:///{(tmp_path / 'replay-service.db').as_posix()}"
    ledger = LedgerStore(database_url)
    coordinator = CoordinatorStore(database_url)
    CognitiveBase.metadata.create_all(coordinator.engine)
    artifact_store = ContentAddressedArtifactStore(
        tmp_path / "artifacts",
        max_artifact_bytes=64 * 1024 * 1024,
    )
    orchestrator = cast(Any, SimpleNamespace(settings=SimpleNamespace()))
    service = RunService(orchestrator, ledger, EventHub(), coordinator, artifact_store)
    yield service
    ledger.close()
    coordinator.close()


def _terminal_state(run_id: str, *, summary: str = "Verified deterministic report") -> AgentState:
    report = AgentReport(
        run_id=run_id,
        status=RunStatus.COMPLETED,
        executive_summary=summary,
        generated_at=FIXED_TIME,
    )
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(
            objective="Audit the repository",
            target_scope=["src"],
            constraints=[f"authorization=Bearer {SECRET}"],
        ),
        status=RunStatus.COMPLETED,
        input_artifacts=[
            InputArtifact(
                artifact_id="input-1",
                original_name="project.zip",
                relative_path="project.zip",
                sha256="1" * 64,
                size_bytes=42,
                media_type="application/zip",
            )
        ],
        report=report,
        started_at=FIXED_TIME,
    )
    with tempfile.TemporaryDirectory(prefix="secmind-replay-admission-") as root:
        artifact_store = ContentAddressedArtifactStore(Path(root) / "artifacts")
        capsule_store = FailureCapsuleStore(Path(root) / "capsules")
        AdmissionService.seal(
            state,
            report,
            artifact_store=artifact_store,
            capsule_store=capsule_store,
        )
    return state


def _seed_database_rows(service: RunService, run_id: str) -> None:
    with Session(service.coordinator.engine) as session:
        session.add(
            ModelInvocationRow(
                model_invocation_id="model-1",
                run_id=run_id,
                step_id="analysis",
                provider_request_id="provider-1",
                model_id="gpt-5.4",
                status="completed",
                input_tokens=10,
                output_tokens=4,
                cost_microunits=7,
                request_hash="2" * 64,
                response_hash="3" * 64,
                created_at=FIXED_TIME,
                updated_at=FIXED_TIME,
            )
        )
        session.add(
            ToolInvocationRow(
                invocation_id="tool-1",
                run_id=run_id,
                step_id="scan",
                tool_name="bandit",
                tool_version="1.7.9",
                idempotency_key="scan-once",
                parameters_hash="4" * 64,
                attempt=1,
                status="completed",
                owner_id="worker-1",
                fence=3,
                result_json=canonical_json(
                    {
                        "status": "success",
                        "data": {"api_key": SECRET},
                        "summary": f"password={SECRET}",
                    }
                ),
                created_at=FIXED_TIME,
                updated_at=FIXED_TIME,
            )
        )
        session.add(
            ApprovalRow(
                request_id="approval-1",
                run_id=run_id,
                step_id="scan",
                tool_name="bandit",
                parameters_hash="5" * 64,
                request_json=canonical_json(
                    {
                        "request_id": "approval-1",
                        "run_id": run_id,
                        "parameters": {"token": SECRET},
                    }
                ),
                status="consumed",
                decision="approve",
                effective_parameters_hash="5" * 64,
                response_json=canonical_json({"decision": "approve", "reason": "authorized"}),
                actor="operator",
                resolution_id="resolution-1",
                consumed_at=FIXED_TIME,
                fence=3,
                created_at=FIXED_TIME,
                resolved_at=FIXED_TIME,
            )
        )
        session.add(
            ArtifactObjectRow(
                artifact_id="6" * 64,
                run_id=run_id,
                invocation_id="tool-1",
                storage_ref=f"66/{'6' * 64}",
                size_bytes=12,
                media_type="application/json",
                created_at=FIXED_TIME,
            )
        )
        session.add(
            StepRunRow(
                step_run_id="step-run-1",
                run_id=run_id,
                step_id="scan",
                attempt=1,
                status="succeeded",
                transition_id="scan-transition",
                fence=1,
                result_json=canonical_json(
                    {
                        "step_id": "scan",
                        "transition_id": "scan-transition",
                        "status": "succeeded",
                        "evidence": [],
                    }
                ),
                created_at=FIXED_TIME,
                updated_at=FIXED_TIME,
            )
        )
        session.commit()


def _archive_contents(service: RunService, artifact_id: str) -> dict[str, bytes]:
    archive = service.artifact_store.read(artifact_id)
    with zipfile.ZipFile(io.BytesIO(archive)) as handle:
        return {name: handle.read(name) for name in handle.namelist()}


def test_service_builds_complete_deterministic_scrubbed_replay(replay_service: RunService) -> None:
    run_id = "run-service-replay"
    state = _terminal_state(run_id, summary=f"api_key={SECRET}")
    replay_service.ledger.save_state(state)
    replay_service.ledger.append(
        run_id,
        "run.completed",
        {"status": "completed", "api_key": SECRET},
        dedupe_key="run-completed",
    )
    _seed_database_rows(replay_service, run_id)

    replay_ref = replay_service.build_replay_bundle(run_id)
    persisted = replay_service.state(run_id)
    verification = replay_service.verify_replay_bundle(run_id)
    replayed = replay_service.deterministic_replay(run_id)
    contents = _archive_contents(replay_service, replay_ref.artifact_id)

    assert persisted.replay_bundle == replay_ref
    assert persisted.state_version == 2
    assert replay_service.get_replay_bundle(run_id) == replay_ref
    assert replay_service.build_replay(run_id) == replay_ref
    assert replay_service.get_replay(run_id) == replay_ref
    assert replay_service.verify_replay(run_id).artifact_id == replay_ref.artifact_id
    assert REQUIRED_REPLAY_ENTRIES.issubset(contents)
    assert verification.model_calls == verification.tool_calls == 0
    assert replayed.model_calls == replayed.tool_calls == 0
    assert replayed.step_patches[0]["step_id"] == "scan"
    assert SECRET.encode() not in replay_service.artifact_store.read(replay_ref.artifact_id)
    assert b"[REDACTED]" in contents["tool-invocations.jsonl"]
    assert b"gpt-5.4" in contents["model-invocations.jsonl"]
    assert b"# SecMind security report" in contents["report.md"]
    assert json.loads(contents["report.sarif"])["version"] == "2.1.0"

    for path, content in contents.items():
        if path.endswith(".json") or path == "manifest.json" or path.endswith(".sarif"):
            assert canonical_json(json.loads(content)).encode() == content, path
        elif path.endswith(".jsonl"):
            for line in content.splitlines():
                assert canonical_json(json.loads(line)).encode() == line, path

    version = replay_service.state(run_id).state_version
    assert replay_service.build_replay_bundle(run_id) == replay_ref
    assert replay_service.state(run_id).state_version == version


def test_service_report_and_replay_ignore_mutable_report_after_admission(replay_service: RunService) -> None:
    run_id = "run-sealed-publication"
    state = _terminal_state(run_id, summary="sealed report summary")
    assert state.sealed_admission is not None
    expected = AdmissionService.project(state.sealed_admission)
    state.report = AgentReport(
        run_id=run_id,
        status=RunStatus.COMPLETED,
        executive_summary="MUTABLE-REPORT-MUST-NOT-LEAK",
    )
    replay_service.ledger.save_state(state)
    replay_service.ledger.append(
        run_id,
        "run.completed",
        {"status": "completed"},
        dedupe_key="run-completed",
    )

    public = replay_service.public_report(run_id)
    replay_ref = replay_service.build_replay_bundle(run_id)
    contents = _archive_contents(replay_service, replay_ref.artifact_id)

    assert public == expected
    assert public.executive_summary == "sealed report summary"
    assert b"MUTABLE-REPORT-MUST-NOT-LEAK" not in contents["report.json"]
    assert json.loads(contents["report.json"])["executive_summary"] == "sealed report summary"


def test_service_rejects_mutable_terminal_report_without_admission(replay_service: RunService) -> None:
    state = _terminal_state("run-unsealed")
    state.sealed_admission = None
    replay_service.ledger.save_state(state)

    with pytest.raises(RuntimeError, match="sealed admission"):
        replay_service.public_report(state.run_id)
    with pytest.raises(ReplayError, match="sealed admission"):
        replay_service.build_replay_bundle(state.run_id)


def test_service_rejects_tampered_sealed_report(replay_service: RunService) -> None:
    state = _terminal_state("run-tampered-admission")
    assert state.sealed_admission is not None
    state.sealed_admission.report.executive_summary = "tampered nested report"
    replay_service.ledger.save_state(state)

    with pytest.raises(RuntimeError, match="mismatch"):
        replay_service.public_report(state.run_id)
    with pytest.raises(ReplayError, match="valid sealed admission"):
        replay_service.build_replay_bundle(state.run_id)


def test_service_replay_rejects_unknown_nonterminal_and_missing_bundle(replay_service: RunService) -> None:
    with pytest.raises(KeyError):
        replay_service.build_replay_bundle("missing")
    with pytest.raises(KeyError):
        replay_service.get_replay_bundle("missing")

    pending = AgentState(run_id="run-pending", task=TaskRequest(objective="Audit pending code"))
    replay_service.ledger.save_state(pending)
    for operation in (
        replay_service.build_replay_bundle,
        replay_service.get_replay_bundle,
        replay_service.verify_replay_bundle,
        replay_service.deterministic_replay,
    ):
        with pytest.raises(RuntimeError, match="terminal"):
            operation(pending.run_id)

    terminal = _terminal_state("run-no-bundle")
    replay_service.ledger.save_state(terminal)
    with pytest.raises(ReplayError, match="has not been built"):
        replay_service.get_replay_bundle(terminal.run_id)
    with pytest.raises(ReplayError, match="has not been built"):
        replay_service.verify_replay_bundle(terminal.run_id)
    with pytest.raises(ReplayError, match="has not been built"):
        replay_service.deterministic_replay(terminal.run_id)


def test_checkpoint_fork_child_replay_preserves_parent_lineage(replay_service: RunService) -> None:
    state = _terminal_state("run-fork-child").model_copy(update={"parent_run_id": "run-parent"})
    replay_service.ledger.save_state(state)

    replay_ref = replay_service.build_replay_bundle(state.run_id)

    assert replay_ref.parent_run_id == "run-parent"
    archive = _archive_contents(replay_service, replay_ref.artifact_id)
    manifest = json.loads(archive["manifest.json"])
    assert manifest["parent_run_id"] == "run-parent"
    assert replay_service.verify_replay_bundle(state.run_id).run_id == state.run_id


def test_replay_reference_cas_reloads_state_after_a_race(
    replay_service: RunService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "run-replay-cas"
    replay_service.ledger.save_state(_terminal_state(run_id))
    real_save = replay_service.ledger.save_state_cas
    calls = 0

    def conflict_once(candidate: AgentState, *, expected_version: int) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            concurrent = replay_service.state(run_id)
            concurrent.completion_reasons.append("concurrent terminal annotation")
            real_save(concurrent, expected_version=expected_version)
            raise RuntimeError("run state version conflict")
        return real_save(candidate, expected_version=expected_version)

    monkeypatch.setattr(replay_service.ledger, "save_state_cas", conflict_once)

    replay_ref = replay_service.build_replay_bundle(run_id)
    persisted = replay_service.state(run_id)

    assert calls == 2
    assert persisted.state_version == 3
    assert persisted.completion_reasons == ["concurrent terminal annotation"]
    assert persisted.replay_bundle == replay_ref
    assert replay_service.verify_replay_bundle(run_id).artifact_id == replay_ref.artifact_id
