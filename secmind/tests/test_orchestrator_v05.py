from __future__ import annotations

import json

from secmind.guardrail import Guardrail
from secmind.ledger import LedgerStore
from secmind.llm import QwenGateway
from secmind.orchestrator import SecMindOrchestrator
from secmind.schemas import (
    AttachmentRef,
    ClaimStatus,
    ClarificationResponse,
    RunStatus,
    Scenario,
    TaskRequest,
)
from secmind.tools import ToolBroker, default_registry


def _orchestrator(settings) -> SecMindOrchestrator:
    settings.prepare_directories()
    return SecMindOrchestrator(
        settings,
        LedgerStore(settings.database_url),
        QwenGateway(settings),
        ToolBroker(default_registry(), Guardrail()),
    )


async def test_ambiguous_task_waits_for_one_shot_clarification_then_resumes(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    orchestrator = _orchestrator(settings)
    run_id = "v05-clarification-run"

    waiting = await orchestrator.start(
        TaskRequest(
            objective="review the attached material",
            attachments=[AttachmentRef(ref="app.py")],
        ),
        run_id,
    )

    assert waiting.status == RunStatus.WAITING_CLARIFICATION
    assert waiting.pending_clarification is not None
    assert waiting.task_spec_ref is not None
    assert waiting.task_spec_ref.revision == 1
    request_id = waiting.pending_clarification.request_id

    completed = await orchestrator.resume_clarification(
        run_id,
        ClarificationResponse(confirmed_scenario=Scenario.CODE_AUDIT),
    )

    assert completed.status == RunStatus.COMPLETED
    assert completed.pending_clarification is None
    assert completed.scenario == Scenario.CODE_AUDIT
    assert completed.task_spec_ref is not None
    assert completed.task_spec_ref.revision == 2
    assert completed.clarifications == [
        {
            "request_id": request_id,
            "resolution_id": completed.clarifications[0]["resolution_id"],
            "task_spec_revision": 2,
        }
    ]

    # The graph interrupt is gone after consumption, so another response cannot
    # dispatch a second resume or create a third TaskSpec revision.
    try:
        await orchestrator.resume_clarification(
            run_id,
            ClarificationResponse(confirmed_scenario=Scenario.LOG_ANALYSIS),
        )
    except RuntimeError as exc:
        assert "no active clarification request" in str(exc)
    else:  # pragma: no cover - explicit security assertion
        raise AssertionError("consumed clarification accepted a second resume")


async def test_code_audit_records_deterministic_strategy_route(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    orchestrator = _orchestrator(settings)

    state = await orchestrator.start(
        TaskRequest(
            objective="audit the attached code",
            attachments=[AttachmentRef(ref="app.py")],
        ),
        "v05-route-run",
    )

    assert state.status == RunStatus.COMPLETED
    assert state.task_spec_ref is not None
    assert state.active_route is not None
    assert state.active_route.run_id == state.run_id
    assert state.active_route.task_spec_digest == state.task_spec_ref.content_digest
    assert state.active_route.scenario == Scenario.CODE_AUDIT
    assert state.active_route.selected_candidate_id in state.active_route.candidate_ids
    assert state.active_route.selected_strategy is not None
    assert state.active_route.route_digest
    assert any(item.decision.startswith("strategy=") for item in state.decisions)


async def test_offline_log_scenario_runs_end_to_end_without_model_or_network(settings) -> None:
    settings.prepare_directories()
    (settings.input_root / "auth.jsonl").write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "timestamp": "2026-07-14T00:00:00Z",
                        "host": "server-01",
                        "message": "Failed password for invalid user from 192.0.2.1",
                    }
                ),
                "malformed-record",
            )
        ),
        encoding="utf-8",
    )
    orchestrator = _orchestrator(settings)

    state = await orchestrator.start(
        TaskRequest(
            objective="analyze the attached security logs and build an evidence-backed timeline",
            attachments=[AttachmentRef(ref="auth.jsonl")],
            target_scope=["auth.jsonl"],
        ),
        "v05-log-scenario",
    )

    assert state.scenario == Scenario.LOG_ANALYSIS
    assert state.status == RunStatus.PARTIAL
    assert state.report is not None
    assert state.report.coverage["network_requests"] == 0
    assert state.report.coverage["provider_requests"] == 0
    assert {item.rule_id for item in state.report.findings} == {"SECMIND-AUTH-BRUTEFORCE-001"}
    assert all(item.evidence_ids for item in state.report.findings)
    assert state.report.status == state.status
    assert all(item.artifact_ref is not None and len(item.artifact_ref) == 64 for item in state.evidence)
    assert all(
        any(claim.status == ClaimStatus.VERIFIED and claim.subject_ref == finding.finding_id for claim in state.claims)
        for finding in state.report.findings
    )
    assert {item.claim_id for item in state.verification_results} <= {item.claim_id for item in state.claims}
    assert set(state.report.claim_ids) == {
        item.claim_id for item in state.claims if item.status == ClaimStatus.VERIFIED
    }
    assert state.budget.usage.provider_requests == 0


async def test_api_static_scenario_runs_end_to_end_and_never_enables_probes(settings) -> None:
    settings.prepare_directories()
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://outside.invalid"}],
        "paths": {
            "/users/{user_id}": {
                "post": {
                    "security": [],
                    "parameters": [],
                }
            }
        },
    }
    (settings.input_root / "openapi.json").write_text(json.dumps(document), encoding="utf-8")
    orchestrator = _orchestrator(settings)

    state = await orchestrator.start(
        TaskRequest(
            objective="perform a static API security assessment of the attached OpenAPI document",
            attachments=[AttachmentRef(ref="openapi.json")],
            target_scope=["openapi.json"],
        ),
        "v05-api-scenario",
    )

    assert state.scenario == Scenario.API_ASSESSMENT
    assert state.report is not None
    assert state.report.coverage["network_requests"] == 0
    assert state.report.coverage["dynamic_probes_enabled"] is False
    assert {item.rule_id for item in state.report.findings} >= {
        "API-AUTH-EXPLICITLY-ABSENT",
        "API-PATH-PARAMETER-UNDECLARED",
        "API-REQUEST-SCHEMA-MISSING",
    }
    assert state.report.status == state.status
    assert all(
        any(claim.status == ClaimStatus.VERIFIED and claim.subject_ref == finding.finding_id for claim in state.claims)
        for finding in state.report.findings
    )
    assert {item.claim_id for item in state.verification_results} <= {item.claim_id for item in state.claims}
    assert "outside.invalid" not in state.report.model_dump_json()
    assert state.budget.usage.provider_requests == 0


async def test_log_scenario_excludes_findings_when_cas_evidence_fails(settings, monkeypatch) -> None:
    settings.prepare_directories()
    (settings.input_root / "auth.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-07-14T00:00:00Z",
                "message": "Failed password for invalid user from 192.0.2.1",
            }
        ),
        encoding="utf-8",
    )
    orchestrator = _orchestrator(settings)

    def unavailable_artifact(_artifact_id: str) -> bytes:
        raise FileNotFoundError("simulated missing CAS object")

    monkeypatch.setattr(orchestrator.artifact_store, "read", unavailable_artifact)
    state = await orchestrator.start(
        TaskRequest(
            objective="analyze the attached security log",
            attachments=[AttachmentRef(ref="auth.jsonl")],
            target_scope=["auth.jsonl"],
        ),
        "v05-log-evidence-rejected",
    )

    # v0.6 treats a missing content-addressed evidence object as a recovery
    # integrity failure, not merely an incomplete analytical result.
    assert state.status == RunStatus.RECOVERY_REQUIRED
    assert state.report is not None
    assert state.report.status == state.status
    assert state.report.findings == []
    assert state.report.claim_ids == []
    assert state.claims
    assert all(item.status == ClaimStatus.REJECTED for item in state.claims)
    assert all(item.status == ClaimStatus.REJECTED for item in state.verification_results)
    assert {item.claim_id for item in state.verification_results} == {item.claim_id for item in state.claims}
    assert any("evidence gate" in item for item in state.report.limitations)
