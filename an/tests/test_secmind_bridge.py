import asyncio
import io
import json
import zipfile

import httpx
import pytest
from test_orchestrator import controlled_orchestrator

from security_agent import secmind_adapter
from security_agent.fusion import classify_task
from security_agent.report_sync import (
    apply_penetration_evidence,
    confirmed_penetration_nodes,
    synchronize_report,
)
from security_agent.schemas import (
    AgentReport,
    AgentState,
    ApprovalDecision,
    ApprovalResponse,
    AttachmentRef,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolStatus,
)
from security_agent.service import EventHub, RunService
from security_agent.tools import WorkspaceSecurityAuditTool
from security_agent.verified_outputs import extract_verified_flags


def context(tmp_path, **kw):
    return ToolContext(run_id="local", step_id="step", workspace=str(tmp_path), allowed_paths=[str(tmp_path)],
        module_base_url="http://engine.test", module_poll_interval_seconds=0.2, module_poll_timeout_seconds=1, **kw)


def report(status="completed", run_id="remote"):
    return {"run_id": run_id, "status": status, "executive_summary": "verified engine report",
        "findings": [{"finding_id": "f1", "rule_id": "r1", "path": "app.py", "title": "Finding",
            "description": "Observed issue", "evidence_ids": ["e1"]}],
        "evidence": [{"evidence_id": "e1", "source": "test", "summary": "actual evidence"}],
        "limitations": [] if status == "completed" else ["one scanner unavailable"]}


def transport(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.asyncio
async def test_archive_preserves_all_relative_paths_and_forwards_contract(tmp_path, monkeypatch):
    files = []
    for i in range(61):
        p = tmp_path / str(i) / "app.py"
        p.parent.mkdir()
        p.write_text("print('safe')", encoding="utf-8")
        files.append(p)
    requests = []
    saved = []
    def handler(request):
        requests.append(request)
        if request.url.path.endswith("/uploads"):
            body = request.content
            start = body.index(b"PK\x03\x04")
            end = body.rindex(b"PK\x05\x06") + 22
            with zipfile.ZipFile(io.BytesIO(body[start:end])) as archive:
                assert set(archive.namelist()) == {str(i) + "/app.py" for i in range(61)}
            return httpx.Response(201, json={"ref": "upload://safe/workspace.zip"})
        if request.url.path.endswith("/tasks"):
            payload = json.loads(request.content)
            assert payload["primary_domain"] == "code_audit_and_patch"
            assert payload["target_scope"] == ["uploaded-source"]
            assert payload["constraints"] == ["read only"]
            assert payload["autonomy_policy"] == "approval_all"
            return httpx.Response(202, json={"run_id": "remote"})
        if request.url.path.endswith("/report"):
            return httpx.Response(200, json=report())
        return httpx.Response(200, json={"run_id": "remote", "status": "completed"})
    transport(monkeypatch, handler)
    async def progress(update):
        saved.append(update)
    ctx = context(tmp_path, target_scope=["uploaded-source"], task_constraints=["read only"],
                  autonomy_policy="approval_all", progress_callback=progress)
    result = await secmind_adapter.invoke_secmind(files, ctx, domain="code_audit_and_patch")
    assert result.status == ToolStatus.SUCCESS
    assert len([r for r in requests if r.url.path.endswith("/tasks")]) == 1
    assert saved[0]["status"] == "submitting"
    assert saved[1]["remote_run_id"] == ctx.external_execution["remote_run_id"] == "remote"


@pytest.mark.asyncio
async def test_restart_polls_saved_id_without_submission(tmp_path, monkeypatch):
    requests = []
    def handler(request):
        requests.append(request.method)
        return httpx.Response(200, json=report() if request.url.path.endswith("/report") else {"status": "completed"})
    transport(monkeypatch, handler)
    result = await secmind_adapter.invoke_secmind([], context(tmp_path, external_execution={"remote_run_id": "remote"}),
        domain="logs_ir_hunting")
    assert result.status == ToolStatus.SUCCESS
    assert requests == ["GET", "GET"]


@pytest.mark.asyncio
async def test_automatic_r3_resolves_remote_approval_without_waiting(tmp_path, monkeypatch):
    source = tmp_path / 'app.py'
    source.write_text('print("ok")', encoding='utf-8')
    approved = False
    resolutions = []

    def handler(request):
        nonlocal approved
        if request.url.path.endswith('/uploads'):
            return httpx.Response(201, json={'ref': 'upload://test'})
        if request.url.path.endswith('/tasks'):
            assert json.loads(request.content)['autonomy_policy'] == 'automatic'
            return httpx.Response(202, json={'run_id': 'remote'})
        if request.url.path.endswith('/approvals/remote-request'):
            resolutions.append(json.loads(request.content))
            approved = True
            return httpx.Response(202, json={'resolution_status': 'accepted'})
        if request.url.path.endswith('/report'):
            return httpx.Response(200, json=report())
        if approved:
            return httpx.Response(200, json={'run_id': 'remote', 'status': 'completed'})
        return httpx.Response(200, json={'run_id': 'remote', 'status': 'waiting_approval',
            'pending_approval': {'request_id': 'remote-request', 'risk_level': 2}})

    transport(monkeypatch, handler)
    ctx = context(tmp_path, autonomy_policy='automatic_r3')
    result = await secmind_adapter.invoke_secmind([source], ctx, domain='code_audit_and_patch')
    assert result.status == ToolStatus.SUCCESS
    assert resolutions == [{'decision': 'approve', 'resolution_id': 'remote-request',
                            'reason': '任务已选择免除所有审批'}]
    assert ctx.external_execution['resolved_approval_ids'] == ['remote-request']


@pytest.mark.asyncio
async def test_transient_poll_error_keeps_remote_identity_and_recovers(tmp_path, monkeypatch):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.RemoteProtocolError("connection closed")
        return httpx.Response(200, json=report() if request.url.path.endswith("/report") else {"status": "completed"})

    transport(monkeypatch, handler)
    ctx = context(tmp_path, external_execution={"remote_run_id": "remote"})
    result = await secmind_adapter.invoke_secmind([], ctx, domain="logs_ir_hunting")
    assert result.status == ToolStatus.SUCCESS
    assert ctx.external_execution["remote_run_id"] == "remote"
    assert calls == 3


@pytest.mark.asyncio
async def test_uncertain_submission_is_not_sent_again(tmp_path, monkeypatch):
    transport(monkeypatch, lambda _: pytest.fail("uncertain POST must not be repeated"))
    result = await secmind_adapter.invoke_secmind([], context(tmp_path, external_execution={"status": "submitting"}), domain="")
    assert result.error_code == "REMOTE_SUBMISSION_UNCERTAIN"


@pytest.mark.asyncio
async def test_partial_report_keeps_evidence_without_success(tmp_path, monkeypatch):
    transport(monkeypatch, lambda req: httpx.Response(200,
        json=report("partial") if req.url.path.endswith("/report") else {"status": "partial"}))
    result = await secmind_adapter.invoke_secmind([], context(tmp_path, external_execution={"remote_run_id": "remote"}), domain="")
    assert result.status == ToolStatus.ERROR
    assert result.data["partial_evidence"]
    assert result.evidence[0].evidence_id == "e1"


@pytest.mark.asyncio
async def test_mismatched_report_is_rejected(tmp_path, monkeypatch):
    transport(monkeypatch, lambda req: httpx.Response(200,
        json=report(run_id="another") if req.url.path.endswith("/report") else {"status": "completed"}))
    with pytest.raises(ValueError, match="身份"):
        await secmind_adapter.invoke_secmind([], context(tmp_path, external_execution={"remote_run_id": "remote"}), domain="")


@pytest.mark.asyncio
async def test_unavailable_full_engine_retains_degraded_local_findings(tmp_path, monkeypatch):
    path = tmp_path / "app.py"
    path.write_text("import subprocess\nsubprocess.Popen('whoami', shell=True)\n")
    transport(monkeypatch, lambda req: httpx.Response(503))
    result = await WorkspaceSecurityAuditTool().invoke({"target": "."}, context(tmp_path, analysis_backend="secmind"))
    assert result.status == ToolStatus.ERROR
    assert result.data["degraded"] and result.data["partial_evidence"]
    assert result.data["findings"]


@pytest.mark.asyncio
async def test_remote_approval_roundtrip_and_failed_ack_is_retryable(settings, monkeypatch):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    state_data = {"approved": False, "attempts": 0, "posts": 0}
    approval = {"request_id": "approve-remote", "tool_name": "analyze", "parameters": {"target": "."},
        "target": "workspace", "risk_level": 2, "reason": "review", "expected_impact": "read"}
    resolutions = []
    def handler(request):
        if "/approvals/" in request.url.path:
            state_data["attempts"] += 1
            payload = json.loads(request.content)
            assert "actor" not in payload
            resolutions.append(payload["resolution_id"])
            if state_data["attempts"] == 1:
                return httpx.Response(503)
            state_data["approved"] = True
            return httpx.Response(202, json={"resolution_status": "accepted"})
        if request.url.path.endswith("/uploads"):
            return httpx.Response(201, json={"ref": "upload://test"})
        if request.url.path.endswith("/tasks"):
            state_data["posts"] += 1
            return httpx.Response(202, json={"run_id": "remote"})
        if request.url.path.endswith("/report"):
            return httpx.Response(200, json=report())
        return httpx.Response(200, json={"status": "completed"} if state_data["approved"] else
            {"status": "waiting_approval", "pending_approval": approval})
    transport(monkeypatch, handler)
    async def invoke(args, ctx):
        from pathlib import Path
        return await secmind_adapter.invoke_secmind(list(Path(ctx.workspace).rglob("*.py")), ctx, domain="code_audit_and_patch")
    tool.invoke = invoke
    task = TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")])
    waiting = await orchestrator.start(task, "remote-approval")
    assert waiting.status == RunStatus.WAITING_APPROVAL
    service = RunService(orchestrator, ledger, EventHub())
    response = ApprovalResponse(decision=ApprovalDecision.APPROVE)
    service.submit_approval(waiting.run_id, response)
    await asyncio.gather(*tuple(service._tasks))
    assert ledger.load_state(waiting.run_id).status == RunStatus.WAITING_APPROVAL
    service.submit_approval(waiting.run_id, response)
    await asyncio.gather(*tuple(service._tasks))
    final = ledger.load_state(waiting.run_id)
    assert final.status == RunStatus.COMPLETED, final.last_error
    assert final.findings[0].evidence_ids == ["e1"]
    assert len(set(resolutions)) == 1
    assert state_data["posts"] == 1
    assert ledger.verify(final.run_id)


@pytest.mark.asyncio
async def test_deadline_requests_external_cancellation(settings, monkeypatch):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    # Leave room for Windows process scheduling and SQLite setup so the
    # deadline expires during the external call, which is the behavior under test.
    settings.max_runtime_seconds = 3
    cancelled = []
    def handler(request):
        cancelled.append((request.method, request.url.path))
        return httpx.Response(202, json={"run_id": "remote", "status": "cancelled"})
    transport(monkeypatch, handler)
    async def invoke(args, ctx):
        await ctx.progress_callback({"module": "secmind", "remote_run_id": "remote", "status": "running"})
        await asyncio.sleep(10)
    tool.invoke = invoke
    final = await orchestrator.start(TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]), "cancel-remote")
    assert final.status == RunStatus.PARTIAL
    assert cancelled == [("POST", "/api/v1/runs/remote/cancel")]
    assert final.external_execution["cancellation_requested"]


@pytest.mark.asyncio
async def test_deadline_cancels_remote_run_when_ledger_snapshot_is_stale(settings, monkeypatch):
    orchestrator, ledger, tool = controlled_orchestrator(settings, RiskLevel.R1)
    settings.max_runtime_seconds = 3
    cancelled = []

    def handler(request):
        cancelled.append((request.method, request.url.path))
        return httpx.Response(202, json={"run_id": "remote", "status": "cancelled"})

    transport(monkeypatch, handler)
    original_load = ledger.load_state
    stale_next_load = False

    def load_state(run_id):
        nonlocal stale_next_load
        state = original_load(run_id)
        if stale_next_load and state is not None:
            stale_next_load = False
            state.external_execution = {}
        return state

    monkeypatch.setattr(ledger, "load_state", load_state)

    async def invoke(args, ctx):
        nonlocal stale_next_load
        await ctx.progress_callback({"module": "secmind", "remote_run_id": "remote", "status": "running"})
        stale_next_load = True
        await asyncio.sleep(10)

    tool.invoke = invoke
    final = await orchestrator.start(
        TaskRequest(objective="audit code", attachments=[AttachmentRef(ref="app.py")]), "cancel-stale-remote"
    )
    assert final.status == RunStatus.PARTIAL
    assert cancelled == [("POST", "/api/v1/runs/remote/cancel")]
    assert final.external_execution["cancellation_requested"]


@pytest.mark.asyncio
async def test_refresh_reads_existing_report_without_model_or_submission(settings, tmp_path, monkeypatch):
    requests = []
    def handler(request):
        requests.append(request.method)
        return httpx.Response(200, json=report() if request.url.path.endswith("/report") else {"status": "completed"})
    transport(monkeypatch, handler)
    state = AgentState(run_id="local", task=TaskRequest(objective="audit code"), status=RunStatus.PARTIAL,
        workspace=str(tmp_path), external_execution={"remote_run_id": "remote"},
        report=AgentReport(run_id="local", status=RunStatus.PARTIAL, executive_summary="old"))
    final = await synchronize_report(state, settings)
    assert final.status == RunStatus.COMPLETED
    assert final.report.run_id == "local" and final.report.findings[0].evidence_ids == ["e1"]
    assert requests == ["GET", "GET"]


@pytest.mark.asyncio
@pytest.mark.parametrize("goal", [False, True])
def _detail_with_bookkeeping_nodes():
    return {
        "project": {"id": "p", "status": "completed"},
        "facts": [
            {"id": "origin", "description": "task origin"},
            {"id": "goal", "description": "get the flag"},
            {"id": "f1", "description": "observed flag{fixture}", "creator": "worker"},
        ],
        "intents": [
            {"id": "i1", "from": ["origin"], "to": "f1", "concluded_at": "now"},
            {"id": "ig", "from": ["f1"], "to": "goal", "concluded_at": "now"},
        ],
        "hints": [{"id": "h1", "content": "module: penetration"}],
    }


def test_confirmed_penetration_nodes_excludes_bookkeeping_nodes():
    nodes = confirmed_penetration_nodes(_detail_with_bookkeeping_nodes())
    raw_ids = {node["raw_id"] for node in nodes}
    assert raw_ids == {"f1"}
    assert all(node["type"] in {"vulnerability", "fact"} for node in nodes)


@pytest.mark.parametrize("node_status", ["completed", "confirmed"])
def test_apply_penetration_evidence_is_idempotent_and_does_not_verify_worker_flags(node_status):
    confirmed = confirmed_penetration_nodes(_detail_with_bookkeeping_nodes())
    confirmed = [{**node, "status": node_status,
                  "description": "Worker reported flag{unverified} without a tool receipt"} for node in confirmed]
    state = AgentState(
        run_id="local",
        task=TaskRequest(objective="authorized lab", target_scope=["https://target.test/"]),
        module_route="penetration",
    )
    first = apply_penetration_evidence(state, "p", confirmed)
    assert first == []
    evidence_ids = {item.evidence_id for item in state.evidence}
    finding_ids = {item.finding_id for item in state.findings}
    assert len(state.findings) == len(confirmed)
    assert all(item.evidence_ids for item in state.findings)

    second = apply_penetration_evidence(state, "p", confirmed)
    assert second == first
    assert {item.evidence_id for item in state.evidence} == evidence_ids
    assert {item.finding_id for item in state.findings} == finding_ids


def test_reclassification_retains_report_references_and_evidence_id():
    detail = {"project": {"id": "p", "status": "completed"}, "facts": [
        {"id": "f001", "description": "Goal achieved via path traversal (LFI). Confirmed payload returned flag.txt contents. Blocked attempts were rejected."}],
        "intents": [], "hints": []}
    state = AgentState(run_id="old", task=TaskRequest(objective="authorized lab"), module_route="penetration")
    old_node = {**confirmed_penetration_nodes(detail)[0], "type": "fact", "severity": "UNKNOWN"}
    apply_penetration_evidence(state, "p", [old_node])
    old_id = state.findings[0].evidence_ids[0]
    for _ in range(2):
        apply_penetration_evidence(state, "p", confirmed_penetration_nodes(detail))
        assert len(state.findings) == len(state.evidence) == 1
        assert state.findings[0].evidence_ids == [old_id]
        assert state.findings[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_repeated_report_refresh_retracts_stale_output_and_preserves_ids(settings, monkeypatch):
    detail = {"project": {"id": "p", "status": "completed"},
              "facts": [{"id": "f001", "description": "Confirmed path traversal (LFI). Confirmed payload returned flag.txt contents."}],
              "intents": [{"id": "done", "to": "goal", "concluded_at": "now"}], "hints": []}
    async def get(*args):
        return detail
    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="old", task=TaskRequest(objective="authorized lab"),
        status=RunStatus.COMPLETED, module_route="penetration", external_execution={"project_id": "p"},
        report=AgentReport(run_id="old", status=RunStatus.COMPLETED,
            executive_summary="Detailed historical summary and citation: evidence-old",
            verified_outputs=["flag{old}"]))
    old_node = {**confirmed_penetration_nodes(detail)[0], "type": "fact", "severity": "UNKNOWN"}
    apply_penetration_evidence(state, "p", [old_node])
    old_evidence_id = state.evidence[0].evidence_id
    for _ in range(2):
        await synchronize_report(state, settings)
        assert "flag{old}" not in state.report.executive_summary
        assert state.report.verified_outputs == []
        assert len(state.report.findings) == len(state.report.evidence) == 1
        assert state.report.findings[0].finding_id == "penetration:p:f001"
        assert state.report.findings[0].evidence_ids == [old_evidence_id]
        assert state.report.findings[0].severity == "HIGH"


@pytest.mark.asyncio
@pytest.mark.parametrize("goal", [False, True])
async def test_flag_fact_alone_does_not_complete_goal_and_findings_have_evidence(settings, monkeypatch, goal):
    async def get(*args):
        return {"project": {"id": "p", "status": "completed"},
            "facts": [{"id": "f1", "description": "observed flag{fixture}", "creator": "worker"}],
            "intents": [{"id": "i1", "from": ["origin"], "to": "f1", "concluded_at": "now"},
                *([{"id": "ig", "from": ["f1"], "to": "goal", "concluded_at": "now"}] if goal else [])]}
    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="local", task=TaskRequest(objective="authorized lab"), status=RunStatus.PARTIAL,
        module_route="penetration", external_execution={"project_id": "p"},
        report=AgentReport(run_id="local", status=RunStatus.PARTIAL, executive_summary="old"))
    final = await synchronize_report(state, settings)
    assert final.status == (RunStatus.COMPLETED if goal else RunStatus.PARTIAL)
    assert final.findings
    assert final.findings[0].evidence_ids
    assert final.findings[0].remediation is None
    assert final.report.verified_outputs == []
    assert "flag{fixture}" not in final.report.executive_summary
    refreshed = await synchronize_report(final, settings)
    assert refreshed.report.verified_outputs == []
    assert refreshed.report.executive_summary.count("flag{fixture}") == 0
    assert len(refreshed.findings) == len(final.findings)


@pytest.mark.asyncio
async def test_legacy_completed_goal_without_verified_flag_stays_partial(settings, monkeypatch):
    async def get(*args):
        return {"project": {"id": "p", "status": "completed"},
            "facts": [{"id": "f1", "description": "Worker reports flag{unverified}"}],
            "intents": [{"id": "ig", "from": ["f1"], "to": "goal", "concluded_at": "now"}]}

    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="legacy-flag", task=TaskRequest(objective="取得 flag"),
        status=RunStatus.COMPLETED, module_route="penetration", external_execution={"project_id": "p"},
        report=AgentReport(run_id="legacy-flag", status=RunStatus.COMPLETED,
            executive_summary="old", verified_outputs=["flag{unverified}"]))

    final = await synchronize_report(state, settings)
    assert final.status == RunStatus.PARTIAL
    assert final.report.verified_outputs == []
    assert "独立核验" in final.last_error


@pytest.mark.asyncio
async def test_refreshed_penetration_report_retracts_removed_goal_and_output(settings, monkeypatch):
    details = [
        {"project": {"id": "p", "status": "completed"},
         "facts": [{"id": "f1", "description": "observed flag{fixture}"}],
         "intents": [{"id": "ig", "from": ["f1"], "to": "goal", "concluded_at": "now"}]},
        {"project": {"id": "p", "status": "stopped"}, "facts": [], "intents": []},
    ]

    async def get(*args):
        return details.pop(0)

    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="local", task=TaskRequest(objective="authorized lab"),
        status=RunStatus.PARTIAL, module_route="penetration",
        external_execution={"project_id": "p"},
        report=AgentReport(run_id="local", status=RunStatus.PARTIAL, executive_summary="old"))
    first = await synchronize_report(state, settings)
    assert first.report.verified_outputs == []
    assert first.status == RunStatus.COMPLETED

    refreshed = await synchronize_report(first, settings)
    assert refreshed.status == RunStatus.PARTIAL
    assert refreshed.report.verified_outputs == []
    assert "flag{fixture}" not in refreshed.report.executive_summary
    assert "目标尚未验证完成" in refreshed.report.executive_summary
    assert not refreshed.report.findings


@pytest.mark.asyncio
async def test_confirmed_runtime_flag_formats_are_exposed_but_unrelated_facts_are_not(settings, monkeypatch):
    async def get(*args):
        return {"project": {"id": "p", "status": "completed"},
            "facts": [
                {"id": "f1", "description": "Recovered value: ctfshow{fixture-123}"},
                {"id": "f2", "description": "The host responds on port 8080"},
            ],
            "intents": [{"id": "i1", "from": ["origin"], "to": "f2", "concluded_at": "now"}]}
    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="local", task=TaskRequest(objective="authorized lab"), status=RunStatus.PARTIAL,
        module_route="penetration", external_execution={"project_id": "p"},
        report=AgentReport(run_id="local", status=RunStatus.PARTIAL, executive_summary="old"))
    final = await synchronize_report(state, settings)
    assert final.report.verified_outputs == []
    assert "ctfshow{fixture-123}" not in final.report.executive_summary


@pytest.mark.asyncio
async def test_runtime_without_verified_flag_has_no_verified_output(settings, monkeypatch):
    async def get(*args):
        return {"project": {"id": "p", "status": "completed"},
            "facts": [{"id": "f1", "description": "The service returned an account name"}], "intents": []}
    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="local", task=TaskRequest(objective="authorized lab"), status=RunStatus.PARTIAL,
        module_route="penetration", external_execution={"project_id": "p"},
        report=AgentReport(run_id="local", status=RunStatus.PARTIAL, executive_summary="old"))
    final = await synchronize_report(state, settings)
    assert final.report.verified_outputs == []
    assert "已验证目标输出" not in final.report.executive_summary


def test_flag_placeholder_in_negative_fact_is_not_verified_output():
    assert extract_verified_flags([
        "目标只返回 404，未获取 flag{...} 或 flag{your_flag_here}",
        "真实证据 ctfshow{fixture-123}",
    ]) == ["ctfshow{fixture-123}"]


@pytest.mark.asyncio
async def test_stopped_project_report_keeps_404_fact_without_placeholder_flag(settings, monkeypatch):
    async def get(*args):
        return {"project": {"id": "p", "status": "stopped"},
            "facts": [{"id": "f1", "description": "Only a 404 wrapper; no flag{...} was found"}],
            "intents": [{"id": "i1", "from": ["origin"], "to": "f1", "concluded_at": "now"}]}

    monkeypatch.setattr("security_agent.report_sync.penetration_get", get)
    state = AgentState(run_id="offline", task=TaskRequest(objective="authorized lab"),
        status=RunStatus.FAILED, module_route="penetration",
        external_execution={"project_id": "p"},
        report=AgentReport(run_id="offline", status=RunStatus.FAILED, executive_summary="old"))
    final = await synchronize_report(state, settings)
    assert final.status == RunStatus.PARTIAL
    assert final.report.verified_outputs == []
    assert final.findings and final.evidence
    assert "已验证目标输出" not in final.report.executive_summary


def test_log_analysis_has_real_route():
    routing = classify_task("分析服务器日志")
    assert routing["primary_type"] == "log_analysis"
    assert routing["scenario"] == Scenario.LOG_ANALYSIS
