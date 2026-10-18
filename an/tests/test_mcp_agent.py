import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_agent.agents import AnalysisOutput, PlanOutput, ReportOutput, RouteOutput, ToolSelectionOutput
from security_agent.api import build_runtime
from security_agent.llm import ModelCallMeta
from security_agent.mcp_runtime import MCPRuntime
from security_agent.schemas import ApprovalResponse, PlanStep, RunStatus, TaskRequest
from security_agent.tools import ToolError


def _codec_tool(methods):
    return {
        "name": "exec_codec",
        "description": "run a codec",
        "inputSchema": {
            "type": "object",
            "properties": {"method": {"type": "string", "enum": list(methods)}},
        },
    }


def test_tool_fingerprint_ignores_scalar_array_order():
    # A Go-map backed server serializes enum arrays in a different order on every
    # probe; the approval fingerprint must not drift because of that.
    assert MCPRuntime.tool_fingerprint(
        _codec_tool(["codec_method_details", "exec_codec"])
    ) == MCPRuntime.tool_fingerprint(_codec_tool(["exec_codec", "codec_method_details"]))


def test_tool_fingerprint_tracks_real_schema_changes():
    baseline = MCPRuntime.tool_fingerprint(_codec_tool(["exec_codec", "codec_method_details"]))
    assert baseline != MCPRuntime.tool_fingerprint(_codec_tool(["exec_codec"]))
    assert baseline != MCPRuntime.tool_fingerprint(_codec_tool(["exec_codec", "decode_base64"]))


def test_tool_fingerprint_keeps_object_arrays_positional():
    first = {"name": "t", "inputSchema": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}
    second = {"name": "t", "inputSchema": {"anyOf": [{"type": "integer"}, {"type": "string"}]}}
    assert MCPRuntime.tool_fingerprint(first) == MCPRuntime.tool_fingerprint(second)
    assert MCPRuntime.tool_fingerprint(first) != MCPRuntime.tool_fingerprint(
        {"name": "t", "inputSchema": {"anyOf": [{"type": "string"}]}}
    )


class SelectingModel:
    """Deterministic model responses; MCP initialize/list/call remains real."""

    settings = SimpleNamespace(demo_mode=False)

    def __init__(self, name, args, scenario="reverse"):
        self.name, self.args, self.scenario = name, args, scenario
        self.prompts = []

    async def structured(self, **kwargs):
        self.prompts.append(kwargs)
        model = kwargs["output_model"]
        if model is RouteOutput:
            output = RouteOutput(primary_type=self.scenario, rationale_summary="MCP integration test")
        elif model is ToolSelectionOutput:
            assert self.name in kwargs["user_prompt"]
            output = ToolSelectionOutput(tool_names=[self.name])
        elif model is PlanOutput:
            assert self.name in kwargs["user_prompt"]
            assert "input_schema" in kwargs["user_prompt"]
            output = PlanOutput(
                steps=[
                    PlanStep(
                        step_id="mcp-test",
                        objective="test",
                        agent_role="executor",
                        tool_candidates=[self.name],
                        inputs=self.args,
                    )
                ],
                rationale_summary="Use discovered MCP tool",
            )
        elif model is AnalysisOutput:
            output = AnalysisOutput(summary="Actual MCP receipt received")
        elif model is ReportOutput:
            assert "mcp:" in kwargs["user_prompt"]
            output = ReportOutput(executive_summary="Verified MCP output in task evidence")
        else:
            raise AssertionError(model)
        return output, ModelCallMeta("test-model", "test", "test", 1, False, {})


def attach_model(orchestrator, model):
    orchestrator.gateway = model
    for agent in (orchestrator.interpreter, orchestrator.planner, orchestrator.analyst, orchestrator.reporter):
        agent.gateway = model


@pytest.mark.parametrize("scenario", ["reverse", "unsupported"])
async def test_agent_selects_real_stdio_tool_and_reports_evidence(settings, scenario):
    service, _, gateway, _ = build_runtime(settings)
    orchestrator = service.orchestrator
    model = SelectingModel("mcp:secmind-local:decode_base64", {"text": "aGVsbG8="}, scenario)
    attach_model(orchestrator, model)
    try:
        state = await orchestrator.start(TaskRequest(objective="Decode the provided Base64 using MCP"), "mcp-e2e")
        assert state.status == RunStatus.COMPLETED, state.last_error
        assert state.budget.tool_calls_used == 1
        assert state.plan[0].tool_candidates == [model.name]
        assert state.plan[0].tool_version
        assert "hello" in state.observations[0].data["output"]
        assert state.report.evidence[0].source == model.name
        assert (
            state.report.evidence[0].sha256
            == hashlib.sha256(Path(state.report.evidence[0].artifact_ref).read_bytes()).hexdigest()
        )
        from security_agent.dashboard import run_bucket

        assert run_bucket(state) == "completed"
        from security_agent.report_sync import synchronize_report

        assert await synchronize_report(state, settings) is state
        receipt = json.loads(Path(state.report.evidence[0].artifact_ref).read_text(encoding="utf-8"))
        assert receipt["run_id"] == state.run_id and receipt["status"] == "completed"
        assert any(e.event_type == "mcp.call.completed" for e in service.ledger.events(state.run_id))
        assert service.ledger.verify(state.run_id)
        assert any(p["output_model"] is ReportOutput and "hello" in p["user_prompt"] for p in model.prompts)
    finally:
        await gateway.close()


async def test_automatic_r3_approves_outside_workspace_mcp_file(settings):
    settings.prepare_directories()
    target = settings.input_root / 'auto-approved.txt'
    target.write_text('approved content', encoding='utf-8')
    service, _, gateway, _ = build_runtime(settings)
    orchestrator = service.orchestrator
    attach_model(orchestrator, SelectingModel('mcp:secmind-local:hash_file', {'path': str(target)}))
    try:
        state = await orchestrator.start(
            TaskRequest(objective='Hash the selected file', autonomy_policy='automatic_r3'),
            'mcp-auto-scope',
        )
        assert state.status == RunStatus.COMPLETED, state.last_error
        assert state.pending_approval is None
        assert any(item['actor'] == 'automatic_r3' and item['decision'] == 'approve'
                   for item in state.approvals)
        assert service.ledger.verify(state.run_id)
        receipt = service.orchestrator.mcp_runtime.store.recent('mcp')[0]
        assert receipt['status'] == 'completed'
    finally:
        await gateway.close()


@pytest.mark.parametrize('autonomy_policy', ['graded', 'automatic'])
async def test_unknown_tool_respects_r2_policy_and_approval_survives_restart(settings, autonomy_policy):
    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    runtime.catalog.create_server(
        {
            "server_id": "test-mcp",
            "name": "test MCP",
            "purpose": "test",
            "enabled": True,
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-m", "security_agent.local_mcp"],
        }
    )
    model = SelectingModel("mcp:test-mcp:decode_base64", {"text": "aGVsbG8="})
    attach_model(service.orchestrator, model)
    try:
        waiting = await service.orchestrator.start(
            TaskRequest(objective="Decode using test MCP", autonomy_policy=autonomy_policy,
                        network_policy="read_only_http"), "mcp-approve"
        )
        if autonomy_policy == 'automatic':
            assert waiting.status == RunStatus.COMPLETED, waiting.last_error
            assert waiting.budget.tool_calls_used == 1
            assert len(runtime.store.recent("mcp")) == 1
            return
        assert waiting.status == RunStatus.WAITING_APPROVAL
        assert runtime.store.recent("mcp") == []
        assert waiting.budget.tool_calls_used == 0
        other, _, other_gateway, _ = build_runtime(settings)
        attach_model(other.orchestrator, model)
        try:
            done = await other.orchestrator.resume(waiting.run_id, ApprovalResponse(decision="approve"))
            assert done.status == RunStatus.COMPLETED, done.last_error
            assert done.budget.tool_calls_used == 1
            assert len(runtime.store.recent("mcp")) == 1
        finally:
            await other_gateway.close()
    finally:
        await gateway.close()


@pytest.mark.parametrize("change", ["disabled", "endpoint"])
async def test_revoked_connection_cannot_use_previous_approval(settings, change):
    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    spec = {
        "server_id": "test-mcp",
        "name": "test MCP",
        "purpose": "test",
        "enabled": True,
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "security_agent.local_mcp"],
    }
    runtime.catalog.create_server(spec)
    attach_model(service.orchestrator, SelectingModel("mcp:test-mcp:decode_base64", {"text": "aGVsbG8="}))
    try:
        waiting = await service.orchestrator.start(TaskRequest(objective="Decode using MCP"), "revoked")
        assert waiting.status == RunStatus.WAITING_APPROVAL
        runtime.catalog.update_server(
            "test-mcp",
            dict(
                spec,
                **({"enabled": False} if change == "disabled" else {"args": ["-u", "-m", "security_agent.local_mcp"]}),
            ),
        )
        done = await service.orchestrator.resume(waiting.run_id, ApprovalResponse(decision="approve"))
        assert done.status == RunStatus.FAILED
        assert not runtime.store.recent("mcp")
    finally:
        await gateway.close()


async def test_protocol_drift_and_invalid_arguments_never_call_tool(settings):
    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    try:
        await runtime.refresh_agent_tools()
        tool = service.orchestrator.broker.registry.get("mcp:secmind-local:decode_base64")
        result = await runtime.invoke(
            "secmind-local", "decode_base64", {"text": "aGVsbG8="}, True, expected_tool="outdated"
        )
        assert result["status"] == "failed" and "协议已变更" in result["error"]
        result = await runtime.invoke(
            "secmind-local", "decode_base64", {"wrong": 1}, True, expected_tool=runtime.tool_fingerprint(tool.tool)
        )
        assert result["status"] == "failed"
    finally:
        await gateway.close()


async def test_mcp_call_error_does_not_produce_success_report(settings):
    service, _, gateway, _ = build_runtime(settings)
    attach_model(service.orchestrator, SelectingModel("mcp:secmind-local:decode_base64", {"text": "!invalid!"}))
    try:
        state = await service.orchestrator.start(TaskRequest(objective="Decode invalid Base64 via MCP"), "bad-input")
        assert state.status == RunStatus.PARTIAL
        assert state.observations[-1].error_code == "MCP_CALL_FAILED"
        assert state.report.status == RunStatus.PARTIAL
        assert service.orchestrator.mcp_runtime.store.recent("mcp")[0]["status"] == "failed"
    finally:
        await gateway.close()


async def test_mcp_cannot_run_after_tool_budget_exhaustion(settings):
    from security_agent.schemas import AgentState, BudgetState

    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    try:
        await runtime.refresh_agent_tools()
        tool = service.orchestrator.broker.registry.get("mcp:secmind-local:decode_base64")
        state = AgentState(
            run_id="budget",
            task=TaskRequest(objective="Decode Base64"),
            workspace=str(settings.run_root),
            budget=BudgetState(tool_calls_used=1, max_tool_calls=1),
            plan=[
                PlanStep(
                    step_id="decode",
                    objective="decode",
                    agent_role="executor",
                    tool_candidates=[tool.manifest.name],
                    tool_version=tool.manifest.version,
                    inputs={"text": "aGVsbG8="},
                )
            ],
        )
        service.ledger.save_state(state)
        result = await service.orchestrator._execute({"agent": state.model_dump(mode="json")})
        assert result["agent"]["status"] == RunStatus.PARTIAL
        assert runtime.store.recent("mcp") == []
    finally:
        await gateway.close()


async def test_unavailable_servers_do_not_enter_agent_registry(settings):
    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    runtime.catalog.create_server(
        {
            "server_id": "offline",
            "name": "offline",
            "purpose": "test",
            "enabled": True,
            "transport": "stdio",
            "command": str(settings.run_root / "missing.exe"),
            "args": [],
        }
    )
    try:
        await runtime.refresh_agent_tools()
        assert runtime.store.get("probe:offline")["status"] == "unavailable"
        assert not any(m.name.startswith("mcp:offline:") for m in service.orchestrator.broker.registry.manifests())
        with pytest.raises(ToolError):
            service.orchestrator.broker.registry.get("mcp:offline:scan")
    finally:
        await gateway.close()
