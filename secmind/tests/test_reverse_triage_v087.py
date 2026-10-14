from __future__ import annotations

import hashlib
from contextvars import ContextVar
from pathlib import Path

from conftest import seal_execution_contract
from sqlalchemy.orm import Session

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.domain_answers import ReverseBehaviorAnswer, normalize_domain_answer
from secmind.execution import ToolInvocationRow
from secmind.guardrail import Guardrail
from secmind.investigation.scenarios import ScenarioCompiler, ScenarioCompileRequest
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestration.primary_degradation import degrade_primary
from secmind.orchestration.primary_runtime import (
    fuse_pre_primary_scenario_answer,
    primary_advisory_context,
    record_pre_primary_scenario_result,
)
from secmind.orchestration.scenario_execution import ScenarioExecutor
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AgentState,
    AttachmentRef,
    InputArtifact,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from secmind.task_specs import TaskSpecRepository
from secmind.tools import ToolBroker, default_registry


def _state(tmp_path: Path, run_id: str, content: bytes) -> tuple[ContentAddressedArtifactStore, AgentState]:
    digest = hashlib.sha256(content).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / f"cas-{run_id}")
    store.put(content, expected_sha256=digest, run_id=run_id, media_type="text/x-c")
    state = seal_execution_contract(
        AgentState(
            run_id=run_id,
            task=TaskRequest(
                objective="Identify the core behavior using static evidence only",
                primary_domain="forensics_static_reverse",
                scoring_mode="reverse_behavior",
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            input_artifacts=[
                InputArtifact(
                    artifact_id=f"input-{run_id}",
                    original_name="subject.c",
                    relative_path="subject.c",
                    sha256=digest,
                    size_bytes=len(content),
                    media_type="text/x-c",
                )
            ],
        )
    )
    return store, state


def test_process_hollowing_chain_is_evidence_bound_and_read_only(tmp_path: Path) -> None:
    content = b"\n".join(
        (
            b"CreateProcessA(target, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);",
            b"NtUnmapViewOfSection(pi.hProcess, base);",
            b"VirtualAllocEx(pi.hProcess, base, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);",
            b"WriteProcessMemory(pi.hProcess, base, image, size, 0);",
            b"SetThreadContext(pi.hThread, &ctx);",
            b"ResumeThread(pi.hThread);",
        )
    )
    store, state = _state(tmp_path, "reverse-hollow", content)

    ScenarioExecutor(store, TaskSpecRepository()).execute_reverse_triage(state)

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    assert answer.behaviors[0]["core_behavior"] == "process_hollowing"
    assert answer.injection[0]["mitre_attack_id"] == "T1055.012"
    assert "process_hollowing" in answer.mitre_attack
    assert answer.c2 and "No C2" in answer.c2
    assert answer.semantic_delta is not None
    assert answer.semantic_delta.evidence_closure.complete is True
    assert answer.semantic_delta.process_provenance.network_access_performed is False
    assert answer.semantic_delta.process_provenance.model_calls == 0
    assert all(row["evidence_ids"] and row["source_locator"] for row in answer.behaviors)
    assert all(item.artifact_ref == state.input_artifacts[0].sha256 for item in state.evidence)
    assert all(item.status.value == "verified" for item in state.claims)


def test_dll_injection_requires_the_complete_remote_chain(tmp_path: Path) -> None:
    complete = b"\n".join(
        (
            b"HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);",
            b"LPVOID remote = VirtualAllocEx(p, 0, n, MEM_COMMIT, PAGE_READWRITE);",
            b"WriteProcessMemory(p, remote, dll_path, n, 0);",
            b"CreateRemoteThread(p, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remote, 0, 0);",
        )
    )
    store, state = _state(tmp_path, "reverse-dll", complete)
    ScenarioExecutor(store, TaskSpecRepository()).execute_reverse_triage(state)
    assert state.report is not None
    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    assert answer.behaviors[0]["core_behavior"] == "dll_injection"
    assert answer.injection[0]["mitre_attack_id"] == "T1055.001"

    incomplete_store, incomplete_state = _state(
        tmp_path,
        "reverse-incomplete",
        b"VirtualAllocEx(p, 0, n, MEM_COMMIT, PAGE_READWRITE);\nWriteProcessMemory(p, remote, x, n, 0);",
    )
    ScenarioExecutor(incomplete_store, TaskSpecRepository()).execute_reverse_triage(incomplete_state)
    assert incomplete_state.report is not None
    incomplete_answer = ReverseBehaviorAnswer.model_validate(incomplete_state.report.answer_payload)
    assert incomplete_answer.behaviors == []
    assert incomplete_answer.injection == []
    assert incomplete_answer.unknowns


def test_apc_rc4_native_and_debug_chain_is_evidence_bound(tmp_path: Path) -> None:
    content = b"\n".join(
        (
            b'GetModuleHandleA("ntdll.dll"); GetProcAddress(module, name);',
            b"rc4_init(&ctx, rc4_key, key_len); rc4_crypt(&ctx, encrypted_shellcode, size);",
            b"NtOpenProcess(&process, access, &attributes, &client_id);",
            b"NtQueryInformationProcess(process, 7, &debugPort, sizeof(debugPort), &size);",
            b"if (debugPort == 0xFFFFFFFF) return 0;",
            b"NtAllocateVirtualMemory(process, &base, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);",
            b"NtWriteVirtualMemory(process, base, encrypted_shellcode, size, &written);",
            b"NtQueueApcThread(thread, base, base, 0, 0);",
            b"NtAlertResumeThread(thread, &previous);",
        )
    )
    store, state = _state(tmp_path, "reverse-apc", content)

    ScenarioExecutor(store, TaskSpecRepository()).execute_reverse_triage(state)

    assert state.report is not None
    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    behaviors = {str(row.get("core_behavior")) for row in answer.behaviors}
    assert {"apc_injection", "encrypted_payload_decryption", "dynamic_native_api_resolution"} <= behaviors
    assert any(row.get("mitre_attack_id") == "T1055.004" for row in answer.injection)
    assert any(row.get("mitre_attack_id") == "T1622" for row in answer.evasion)
    assert {"T1027", "T1055.004", "T1106", "T1622"} <= set(answer.mitre_attack)
    assert answer.semantic_delta is not None
    assert answer.semantic_delta.evidence_closure.complete is True
    assert all(row.get("evidence_ids") for row in [*answer.behaviors, *answer.evasion])


def test_empty_reverse_signature_result_does_not_negative_prime_primary(tmp_path: Path) -> None:
    store, state = _state(tmp_path, "reverse-no-signal", b"int main(void) { return 0; }")
    ScenarioExecutor(store, TaskSpecRepository()).execute_reverse_triage(state)
    record_pre_primary_scenario_result(state)
    host = type("Host", (), {"settings": type("Settings", (), {"primary_advisory_context_bytes": 4096})()})()

    assert primary_advisory_context(host, state) == []
    assert state.audit_coverage["primary_advisory_context"]["scope"] == "reverse_no_positive_signal"


def test_reverse_triage_invokes_pe_reverse_tool_for_pe_samples(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    sample = repo_root / "reverse_evaluation" / "fixtures" / "safe-demo-v1" / "build" / "reverse_demo.exe"
    copied = tmp_path / "reverse_demo.exe"
    copied.write_bytes(sample.read_bytes())
    digest = hashlib.sha256(copied.read_bytes()).hexdigest()
    store = ContentAddressedArtifactStore(tmp_path / "cas-reverse-pe")
    store.put(
        copied.read_bytes(), expected_sha256=digest, run_id="reverse-pe-call", media_type="application/x-msdownload"
    )
    state = seal_execution_contract(
        AgentState(
            run_id="reverse-pe-call",
            task=TaskRequest(
                objective="Statically identify the core behavior using PE reverse analysis",
                primary_domain="forensics_static_reverse",
                scoring_mode="reverse_behavior",
            ),
            scenario=Scenario.REVERSE_TRIAGE,
            workspace=str(tmp_path),
            input_artifacts=[
                InputArtifact(
                    artifact_id="input-reverse-pe-call",
                    original_name="reverse_demo.exe",
                    relative_path="reverse_demo.exe",
                    sha256=digest,
                    size_bytes=copied.stat().st_size,
                    media_type="application/x-msdownload",
                )
            ],
        )
    )

    broker = ToolBroker(default_registry(), Guardrail())
    ScenarioExecutor(store, TaskSpecRepository(), broker=broker).execute_reverse_triage(state)

    assert state.report is not None
    assert state.audit_coverage["reverse_pe_tool"]["tool_name"] == "pe_reverse_analysis"
    assert state.audit_coverage["reverse_pe_tool"]["status"] == "success"
    with Session(broker.execution_store.engine) as session:
        rows = session.query(ToolInvocationRow).filter(ToolInvocationRow.run_id == state.run_id).all()
    assert any(row.tool_name == "pe_reverse_analysis" for row in rows)
    assert any(row.status == "completed" for row in rows)


def test_reverse_pe_tool_uses_the_active_run_lease(tmp_path: Path) -> None:
    """The scenario tool call must carry the Worker fence to the broker."""

    store, state = _state(tmp_path, "reverse-pe-lease", b"MZ")
    state.workspace = str(tmp_path)
    state.lease.owner_id = "worker-under-test"
    state.lease.fence = 7
    executor = ScenarioExecutor(store, TaskSpecRepository())
    artifact = InputArtifact(
        artifact_id="input-reverse-pe-lease",
        original_name="sample.exe",
        relative_path="sample.exe",
        sha256=hashlib.sha256(b"MZ").hexdigest(),
        size_bytes=2,
        media_type="application/x-msdownload",
    )

    captured: dict[str, object] = {}

    class Broker:
        async def execute(self, _name, _args, context, **_kwargs):
            captured["lease_owner_id"] = context.lease_owner_id
            captured["lease_fence"] = context.lease_fence
            return ToolResult(status=ToolStatus.SUCCESS)

    executor.broker = Broker()
    executor._invoke_reverse_pe_tool(state, artifact)

    assert captured == {"lease_owner_id": "worker-under-test", "lease_fence": 7}


def test_reverse_projection_survives_primary_success_and_failure(tmp_path: Path) -> None:
    content = b"\n".join(
        (
            b"OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);",
            b"VirtualAllocEx(p, 0, n, MEM_COMMIT, PAGE_READWRITE);",
            b"WriteProcessMemory(p, remote, dll_path, n, 0);",
            b"CreateRemoteThread(p, 0, 0, LoadLibraryW, remote, 0, 0);",
        )
    )
    store, state = _state(tmp_path, "reverse-fusion", content)
    ScenarioExecutor(store, TaskSpecRepository()).execute_reverse_triage(state)
    projection = record_pre_primary_scenario_result(state)
    assert projection is not None

    provider = normalize_domain_answer(
        "reverse_behavior",
        {
            "task_id": state.run_id,
            "status": "completed",
            "executive_summary": "Provider supplied additional context.",
            "behaviors": [{"behavior": "manual export resolution"}],
            "unknowns": [],
        },
    )
    fused = fuse_pre_primary_scenario_answer(state, provider)
    names = {str(row.get("behavior")) for row in fused.behaviors if isinstance(row, dict)}
    assert {"dll_injection", "manual export resolution"} <= names
    assert fused.semantic_delta is not None

    degrade_primary(state, "provider read-idle deadline", attempted=True, provider_requests=2)
    assert state.report is not None
    preserved = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    assert preserved.behaviors[0]["core_behavior"] == "dll_injection"
    assert state.status == RunStatus.PARTIAL


def test_reverse_scenario_is_compiled_and_routed_before_primary() -> None:
    compilation = ScenarioCompiler().compile(
        ScenarioCompileRequest(
            run_id="reverse-plan",
            scenario=Scenario.REVERSE_TRIAGE,
            objective="Statically identify the core behavior",
            immutable_scope=(".",),
        )
    )
    assert compilation.release_enabled is True
    assert compilation.execution_mode.value == "static"
    assert compilation.plan_proposal.proposed_steps[0].capability == "static_file_triage"

    orchestrator = object.__new__(SecMindOrchestrator)
    orchestrator.settings = type(
        "Settings",
        (),
        {
            "enable_log_analysis": False,
            "enable_incident_dry_run": False,
            "enable_api_static_assessment": False,
        },
    )()
    orchestrator._active_authority = ContextVar("reverse_route_authority", default=None)
    state = AgentState(
        run_id="reverse-route",
        task=TaskRequest(objective="reverse"),
        scenario=Scenario.REVERSE_TRIAGE,
    )
    assert orchestrator._pre_primary_evidence_route({"agent": state.model_dump(mode="json")}) == "scenario"


async def test_offline_graph_keeps_verified_reverse_fallback(settings) -> None:
    content = b"\n".join(
        (
            b"OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);",
            b"VirtualAllocEx(p, 0, n, MEM_COMMIT, PAGE_READWRITE);",
            b"WriteProcessMemory(p, remote, dll_path, n, 0);",
            b"CreateRemoteThread(p, 0, 0, LoadLibraryA, remote, 0, 0);",
        )
    )
    settings.prepare_directories()
    (settings.input_root / "subject.c").write_bytes(content)
    ledger = LedgerStore(settings.database_url)
    orchestrator = SecMindOrchestrator(
        settings,
        ledger,
        QwenGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
    )

    state = await orchestrator.start(
        TaskRequest(
            objective="Identify the core behavior using static evidence only",
            attachments=[AttachmentRef(ref="subject.c")],
            primary_domain="forensics_static_reverse",
            scoring_mode="reverse_behavior",
            expected_outputs=["evidence_backed_reverse_behavior"],
        ),
        "reverse-offline-graph",
    )

    assert state.status == RunStatus.COMPLETED
    assert state.report is not None
    answer = ReverseBehaviorAnswer.model_validate(state.report.answer_payload)
    assert answer.behaviors[0]["core_behavior"] == "dll_injection"
    assert state.audit_coverage["pre_primary_scenario_executed"] is True
    assert state.audit_coverage["canonical_primary_attempted"] is False
    assert state.report.evidence
