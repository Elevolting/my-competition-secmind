from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from conftest import seal_execution_contract

from secmind.admission import AdmissionService
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import FindingAnswer
from secmind.firmware_audit import FirmwareAuditLimits, FirmwareAuditSource, audit_firmware_sources
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import AgentState, InputArtifact, RunStatus, TaskRequest
from secmind.task_context import ResolvedTaskContractRequired
from secmind.task_specs import TaskSpecRepository


def _state_with_artifact(
    tmp_path: Path,
    *,
    run_id: str,
    relative_path: str,
    content: bytes,
    store_input: bool = True,
) -> tuple[ContentAddressedArtifactStore, AgentState]:
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / f"cas-{run_id}")
    if store_input:
        store.put(content, expected_sha256=digest, run_id=run_id, media_type="text/plain")
    artifact = InputArtifact(
        artifact_id=f"artifact-{run_id}",
        original_name=Path(relative_path).name,
        relative_path=relative_path,
        sha256=digest,
        size_bytes=len(content),
        media_type="text/plain",
    )
    state = seal_execution_contract(
        AgentState(
            run_id=run_id,
            task=TaskRequest(
                objective="Perform a read-only firmware static audit",
                primary_domain="complex_input_understanding",
                secondary_capabilities=["firmware_static_audit"],
                scoring_mode="security_finding",
            ),
            input_artifacts=[artifact],
        )
    )
    return store, state


def test_firmware_audit_emits_evidence_bound_findings_for_explicit_risks(tmp_path: Path, admission_stores) -> None:
    content = (
        b"root:$1$salt$abcdefghijklmnop\n"
        b'wireless.ssid.datatype="maxlength(300)"\n'
        b'firmware_update_url="http://updates.example.invalid/image.bin"\n'
        b'local country = request.formvalue("country")\n'
        b'os.execute("iw reg set " .. country)\n'
    )
    store, state = _state_with_artifact(
        tmp_path,
        run_id="firmware-positive",
        relative_path="artifact_01.bak",
        content=content,
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = FindingAnswer.model_validate(state.report.answer_payload)
    rule_ids = {str(row["rule_id"]) for row in answer.findings}
    assert {
        "FW-WEAK-CREDENTIAL-HASH",
        "FW-WIRELESS-INPUT-LENGTH",
        "FW-CLEARTEXT-TRANSPORT",
        "FW-UNTRUSTED-SHELL-DATAFLOW",
    } <= rule_ids
    assert answer.extensions["network_requests"] == 0
    assert answer.extensions["execution_performed"] is False
    assert all(row["evidence_ids"] and row["source_locator"] for row in answer.findings)
    assert all(row["source_locator"]["source_ref"] == "artifact_01.bak" for row in answer.findings)
    assert all(item.metadata["source_locator"]["byte_length"] >= 0 for item in state.evidence)
    _artifact_store, capsule_store = admission_stores
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=store,
        capsule_store=capsule_store,
    )
    assert snapshot.admitted_finding_ids
    assert set(snapshot.admitted_finding_ids) == {item.finding_id for item in state.findings}
    assert snapshot.report.evidence


def test_firmware_audit_does_not_publish_guarded_or_non_vulnerable_patterns(tmp_path: Path) -> None:
    content = (
        b'ssid.datatype="maxlength(32)"\n'
        b'firmware_update_url="https://updates.example.invalid/image.bin"\n'
        b'local country = request.formvalue("country")\n'
        b'luci.sys.call("iw reg set %s" % shellquote(country))\n'
        b'os.execute("hostapd -veap")\n'
    )
    store, state = _state_with_artifact(
        tmp_path,
        run_id="firmware-negative",
        relative_path="safe.conf",
        content=content,
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_firmware_static_audit(state)

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = FindingAnswer.model_validate(state.report.answer_payload)
    assert answer.findings == []
    assert answer.negative_evidence
    assert all(row["evidence_ids"] and row["source_locator"] for row in answer.negative_evidence)
    assert any(row.get("kind") == "guarded_shell_sink" for row in answer.negative_evidence)


def test_firmware_audit_preserves_utf16_source_offsets(tmp_path: Path) -> None:
    content = b"\xff\xfe" + "root:$1$salt$abcdefghijklmnop\n".encode("utf-16le")
    store, state = _state_with_artifact(
        tmp_path,
        run_id="firmware-utf16",
        relative_path="shadow.bak",
        content=content,
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_firmware_static_audit(state)

    assert state.report is not None
    answer = FindingAnswer.model_validate(state.report.answer_payload)
    row = answer.findings[0]
    locator = row["source_locator"]
    observed = content[locator["byte_offset"] : locator["byte_offset"] + locator["byte_length"]]
    assert observed.decode("utf-16le") == "$1$salt$abcdefghijklmnop"


def test_firmware_audit_budget_drops_unbound_findings_fail_closed() -> None:
    content = b"root:$1$salt$abcdefghijklmnop\n"
    digest = hashlib.sha256(content).hexdigest()
    artifact = InputArtifact(
        artifact_id="artifact-budget",
        original_name="shadow.bak",
        relative_path="shadow.bak",
        sha256=digest,
        size_bytes=len(content),
        media_type="text/plain",
    )
    result = audit_firmware_sources(
        [FirmwareAuditSource(artifact=artifact, content=content)],
        limits=FirmwareAuditLimits(max_evidence=1),
    )

    assert result.status == RunStatus.PARTIAL
    assert result.findings == ()
    assert result.evidence
    assert any("evidence budget" in item for item in result.limitations)


def test_firmware_delta_is_admitted_after_primary_without_mutating_anchor(tmp_path: Path, admission_stores) -> None:
    content = b"root:$1$salt$abcdefghijklmnop\n"
    store, state = _state_with_artifact(
        tmp_path,
        run_id="firmware-primary-delta",
        relative_path="shadow.bak",
        content=content,
    )
    executor = ScenarioExecutor(store, TaskSpecRepository())
    executor.execute_firmware_static_audit(state)
    assert state.report is not None
    firmware_finding_ids = {item.finding_id for item in state.findings}
    primary_report = state.report.model_copy(
        update={
            "executive_summary": "Primary baseline without a firmware conclusion",
            "findings": [],
            "evidence": [],
            "answer_payload": {"findings": []},
        }
    )
    state.report = primary_report
    state.audit_coverage.update(
        {
            "direct_anchor_pipeline": True,
            "direct_anchor_strict": True,
            "canonical_primary_completed": True,
        }
    )
    _artifact_store, capsule_store = admission_stores
    response = store.put(b"firmware primary response", run_id=state.run_id, media_type="application/json")
    AdmissionService.admit_baseline(
        state,
        artifact_store=store,
        capsule_store=capsule_store,
        model_id="fixture-primary",
        prompt_version="fixture",
        prompt_artifact_id=None,
        request_sha256="a" * 64,
        response_sha256=response.sha256,
        response_schema_sha256="c" * 64,
        context_sha256="d" * 64,
        response_artifact_id=response.artifact_id,
        provider_requests=0,
        input_tokens=0,
        output_tokens=0,
        cost_units=0,
        status=RunStatus.COMPLETED,
        executive_summary=primary_report.executive_summary,
        answer_type="finding",
        answer_payload={"findings": []},
        findings=[],
        evidence=[],
        decisions=[],
        limitations=[],
        coverage=dict(state.audit_coverage),
    )

    SecMindOrchestrator._register_verified_scenario_deltas(state)

    delta_rows = [
        item
        for item in state.audit_coverage.get("typed_deltas", [])
        if isinstance(item, dict) and item.get("finding", {}).get("finding_id") in firmware_finding_ids
    ]
    assert delta_rows
    assert all(item["action"] == "added" and item["admission_ready"] for item in delta_rows)
    assert state.published_baseline is not None
    assert state.published_baseline.findings == []
    snapshot = AdmissionService.seal(
        state,
        state.report,
        artifact_store=store,
        capsule_store=capsule_store,
    )
    assert firmware_finding_ids <= set(snapshot.admitted_finding_ids)
    assert snapshot.report.findings
    assert snapshot.report.coverage["primary_preserved"] is True
    assert snapshot.report.coverage["accepted_delta_count"] >= len(delta_rows)


def test_firmware_audit_missing_cas_is_partial_and_not_empty_completed(tmp_path: Path) -> None:
    store, state = _state_with_artifact(
        tmp_path,
        run_id="firmware-cas-gap",
        relative_path="config.bak",
        content=b"root:$1$salt$abcdefghijklmnop\n",
        store_input=False,
    )

    ScenarioExecutor(store, TaskSpecRepository()).execute_firmware_static_audit(state)

    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    answer = FindingAnswer.model_validate(state.report.answer_payload)
    assert answer.execution_status == "partial"
    assert answer.epistemic_status == "insufficient_evidence"
    assert answer.limitations
    assert answer.findings == []


def test_firmware_dispatch_requires_a_sealed_contract(tmp_path: Path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "cas-no-contract")
    state = AgentState(
        run_id="firmware-no-contract",
        task=TaskRequest(
            objective="Perform a read-only firmware static audit",
            secondary_capabilities=["firmware_static_audit"],
        ),
    )

    with pytest.raises(ResolvedTaskContractRequired, match="sealed"):
        ScenarioExecutor(store, TaskSpecRepository()).execute_log_analysis(state)
