from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secmind.domain_answers import normalize_domain_answer
from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestration.evidence_compiler_runtime import compile_evidence
from secmind.orchestration.primary_degradation import recover_primary_projection_validation
from secmind.orchestration.primary_runtime import fuse_pre_primary_scenario_answer
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import AgentState, Evidence, RunStatus, Scenario, TaskRequest
from secmind.task_contract import EvidenceCompilerReceipt, EvidenceFact, compile_resolved_task_contract
from secmind.tools import ToolBroker, default_registry


def _evidence_gap_contract(run_id: str):
    return compile_resolved_task_contract(
        {
            "task_spec_id": f"spec-{run_id}",
            "run_id": run_id,
            "revision": 1,
            "content_digest": hashlib.sha256(f"spec:{run_id}".encode()).hexdigest(),
            "objectives": ["Determine whether supplied telemetry supports attribution"],
            "primary_scenario": Scenario.UNKNOWN.value,
            "primary_domain": "orchestration_recovery_uncertainty",
            "secondary_scenarios": [],
            "secondary_capabilities": ["evidence_gap_handling"],
            "scoring_mode": "evidence_gap",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["telemetry.log"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": ["evidence_gap_assessment"],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": [],
        },
        input_manifest_digest="a" * 64,
    )


@pytest.mark.asyncio
async def test_real_domain_fusion_failure_recovers_as_typed_gap(settings) -> None:
    """Exercise normalize→fusion→recovery, rather than mocking the graph node."""

    run_id = "run-real-domain-fusion-recovery"
    contract = _evidence_gap_contract(run_id)
    source_sha256 = "a" * 64
    fact = EvidenceFact(
        fact_id="fact-lfs-real",
        fact_type="artifact.git_lfs_pointer",
        value={
            "relative_path": "telemetry.log",
            "pointer_oid": "b" * 64,
            "declared_size": 1_478_202,
            "underlying_object_present": False,
            "attribution_permitted": False,
        },
        source_ref="telemetry.log",
        source_sha256=source_sha256,
        locator="whole-file",
    )
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="Determine whether supplied telemetry supports attribution"),
        scenario=Scenario.UNKNOWN,
        status=RunStatus.RUNNING,
        resolved_task_contract=contract,
        evidence_compiler_receipt=EvidenceCompilerReceipt(
            run_id=run_id,
            contract_digest=contract.contract_digest,
            input_manifest_digest=contract.input_manifest_digest,
            facts=[fact],
            raw_window_refs=[source_sha256],
            output_digest="c" * 64,
        ),
        evidence=[
            Evidence(
                evidence_id="evidence-lfs-real",
                source="test:evidence-compiler",
                summary="The supplied input is a Git LFS pointer.",
                sha256=source_sha256,
            )
        ],
        audit_coverage={
            "pre_primary_scenario_projection": {
                "scenario": Scenario.UNKNOWN.value,
                "answer_kind": "evidence_gap",
                # This is the actual payload shape consumed by the fusion
                # routine.  The invalid nested graph makes the strict second
                # validation fail at the real projection boundary.
                "answer_payload": {
                    "answer_kind": "evidence_gap",
                    "semantic_output": {"missing": "evidence_closure"},
                },
            }
        },
    )
    typed = normalize_domain_answer(
        "evidence_gap",
        {"task_id": run_id, "status": "partial", "executive_summary": "provider answer"},
    )
    with pytest.raises(ValidationError) as captured:
        fuse_pre_primary_scenario_answer(state, typed)
    assert any(item["loc"][0] == "semantic_output" for item in captured.value.errors())

    settings.model_mode = "offline"
    gateway = QwenGateway(settings)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, gateway, broker)
    ledger.save_state(state)
    try:
        output = await recover_primary_projection_validation(
            orchestrator,
            {"agent": state.model_dump(mode="json")},
            captured.value,
            state=state,
            attempted=False,
        )
        recovered = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert recovered.status == RunStatus.PARTIAL
    assert recovered.report is not None
    assert recovered.report.answer_type == "evidence_gap"
    assert recovered.report.answer_payload["epistemic_status"] == "insufficient_evidence"
    assert recovered.report.evidence[0].evidence_id == "evidence-lfs-real"
    failure = recovered.audit_coverage["canonical_primary_projection_failure"]
    assert failure["failure_stage"] == "post_provider_projection"
    assert any(item["location"][0] == "semantic_output" for item in failure["issues"])


@pytest.mark.asyncio
async def test_evidence_receipt_validation_degrades_to_primary(settings, monkeypatch) -> None:
    """A malformed aggregate receipt must not exhaust the worker retry budget."""

    run_id = "run-evidence-receipt-validation"
    contract = _evidence_gap_contract(run_id)
    state = AgentState(
        run_id=run_id,
        task=TaskRequest(objective="Compile bounded evidence"),
        scenario=Scenario.UNKNOWN,
        status=RunStatus.RUNNING,
        resolved_task_contract=contract,
    )
    settings.model_mode = "offline"
    gateway = QwenGateway(settings)
    ledger = LedgerStore(settings.database_url)
    broker = ToolBroker(default_registry(), Guardrail())
    orchestrator = SecMindOrchestrator(settings, ledger, gateway, broker)
    ledger.save_state(state)

    # Corrupt only the generated aggregate digest.  The parser/evidence node
    # still runs normally; this injects the exact model-validation boundary
    # without replacing compile_evidence itself.
    import secmind.orchestration.evidence_compiler_runtime as runtime

    monkeypatch.setattr(runtime, "canonical_digest", lambda _payload: "not-a-sha256")
    try:
        output = await compile_evidence(orchestrator, {"agent": state.model_dump(mode="json")})
        recovered = AgentState.model_validate(output["agent"])
    finally:
        broker.close()
        ledger.close()

    assert output["route"] == "primary"
    assert recovered.status == RunStatus.PARTIAL
    assert recovered.evidence_compiler_receipt is None
    failure = recovered.audit_coverage["evidence_compiler_validation_failure"]
    assert failure["failure_stage"] == "evidence_compiler_receipt"
    assert failure["error_type"] == "ValidationError"
    assert failure["recovery_route"] == "primary"
    assert any(item["location"] == ["output_digest"] for item in failure["issues"])
