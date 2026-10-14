"""Expose discovered MCP tools through the task's normal tool broker."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import quote

from security_agent.mcp_scope import validate_target_scope
from security_agent.schemas import Evidence, RiskLevel, Scenario, ToolManifest, ToolResult, ToolStatus
from security_agent.tools import BaseTool, ToolError, ToolRegistry

# Only locally reviewed pure transformations get automatic R1 treatment.
# Server annotations are informational, not permission grants.
PURE_TOOLS = {
    "secmind-local": {"decode_base64"},
    "local-burp": {"base64_encode", "base64_decode", "url_encode", "url_decode"},
    "local-tscanplus": {"jwt_decode"},
}


def tool_id(server_id, name):
    return "mcp:" + quote(server_id, safe="") + ":" + quote(name, safe="")


class MCPAgentTool(BaseTool):
    def __init__(self, runtime, server, tool):
        self.runtime, self.server, self.tool = runtime, server, tool
        from security_agent.mcp_approval import destructive_tool, offline_safe
        pure = tool["name"] in PURE_TOOLS.get(server["server_id"], set())
        destructive = destructive_tool(server['server_id'], tool['name'], server.get('risk_level'))
        self.manifest = ToolManifest(
            name=tool_id(server["server_id"], tool["name"]),
            version=runtime.connection_fingerprint(server) + ":" + runtime.tool_fingerprint(tool),
            description=f"{server['name']} / {tool['name']}: {tool.get('description') or ''}",
            scenarios=list(Scenario),
            input_schema=tool["inputSchema"],
            output_schema={"type": "object"},
            risk_level=RiskLevel.R3 if destructive else RiskLevel.R1 if pure else RiskLevel.R2,
            permissions=["mcp:invoke"],
            timeout_seconds=90 if server['server_id'] == 'kali-tools' else 65,
            idempotent=pure,
            requires_network=not offline_safe(server['server_id'], tool['name']),
        )

    async def invoke(self, args, context):
        started = time.monotonic()
        try:
            from security_agent.mcp_approval import offline_safe, requires_approval, requires_context_approval
            state = self.runtime.ledger.load_state(context.run_id)
            if state is None or state.status.value != 'running':
                raise ValueError('MCP 任务已结束或不存在')
            digest = hashlib.sha256(json.dumps([self.manifest.name, args],
                sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            planned = next((item for item in state.plan if item.step_id == context.step_id), None)
            approval = next((item for item in reversed(state.approvals)
                if item.get('step_id') == context.step_id
                and item.get('parameters_sha256') == digest
                and item.get('decision') in {'approve', 'edit'}), None)
            if approval and (planned is None or planned.tool_version != self.manifest.version):
                approval = None
            scope_approval = approval if approval and int(approval.get('risk_level', -1)) >= 3 else None
            from security_agent.guardrail import autonomy_policy_skips_approval
            risk_approval = (requires_approval(self.server['server_id'], self.tool['name'], args)
                             and not autonomy_policy_skips_approval(
                                 self.manifest.risk_level, state.task.autonomy_policy))
            if (requires_context_approval(self.server['server_id'], self.tool['name'])
                    or risk_approval) and approval is None:
                raise ValueError('MCP 调用没有与参数及工具版本匹配的逐次审批')
            if state.task.network_policy == 'none' and not offline_safe(
                    self.server['server_id'], self.tool['name']) and scope_approval is None:
                raise ValueError('任务未授权网络访问此 MCP 工具')
            from security_agent.mcp_boundaries import AmbiguousMCPPathError, validate_workbench_arguments
            try:
                validate_workbench_arguments(self.server['server_id'], self.tool['name'],
                                             args, Path(context.workspace))
            except AmbiguousMCPPathError:
                raise
            except ValueError:
                if scope_approval is None:
                    raise
            if not self.manifest.idempotent:
                try:
                    validate_target_scope(self.server["server_id"], args, context.target_scope)
                except ValueError:
                    if scope_approval is None:
                        raise
            request_id = approval['request_id'] if approval else hashlib.sha256(json.dumps(
                [context.run_id, context.step_id, self.manifest.version, args],
                sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:32]
            receipt = await self.runtime.invoke(
                self.server["server_id"],
                self.tool["name"],
                args,
                approved=True,
                run_id=context.run_id,
                expected_connection=self.runtime.connection_fingerprint(self.server),
                expected_tool=self.runtime.tool_fingerprint(self.tool),
                blackboard=context.blackboard or None,
                before_call=context.blackboard_validator,
                request_id=request_id,
                scope_override_step_id=context.step_id if scope_approval else None,
            )
        except ValueError as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="MCP_UNAVAILABLE", error_message=str(exc))
        # Persist the complete receipt; bound what goes back into model context.
        folder = Path(context.workspace) / ".mcp-results"
        folder.mkdir(parents=True, exist_ok=True)
        artifact = folder / (receipt["call_id"] + ".json")
        raw = json.dumps(receipt, ensure_ascii=False, indent=2)
        artifact.write_bytes(raw.encode("utf-8"))
        result = receipt.get("result", {})
        content = "\n".join(
            str(item.get("text", "")) for item in result.get("content", []) if item.get("type") == "text"
        )
        if result.get("structuredContent") is not None:
            content += "\n" + json.dumps(result["structuredContent"], ensure_ascii=False)
        completed = receipt["status"] == "completed"
        structured = result.get("structuredContent") if isinstance(result, dict) else None
        coverage = structured.get("coverage") if isinstance(structured, dict) else None
        evidence = Evidence(
            source=self.manifest.name,
            summary=content[:12000] or receipt.get("error", receipt["status"]),
            artifact_ref=str(artifact),
            sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            metadata={
                "call_id": receipt["call_id"],
                "server_id": self.server["server_id"],
                "tool": self.tool["name"],
                "status": receipt["status"],
            },
        )
        return ToolResult(
            status=ToolStatus.SUCCESS if completed else ToolStatus.ERROR,
            data={
                "adapter": "mcp",
                "call_id": receipt["call_id"],
                "server_id": self.server["server_id"],
                "tool": self.tool["name"],
                "output": content[:24000],
                "output_truncated": len(content) > 24000,
                **({"coverage": coverage} if completed and isinstance(coverage, dict) else {}),
            },
            summary=f"{self.manifest.name}: {receipt['status']}\n{content[:4000]}",
            artifacts=[str(artifact)],
            evidence=[evidence],
            duration_ms=int((time.monotonic() - started) * 1000),
            error_code=None if completed else "MCP_CALL_FAILED",
            error_message=None if completed else receipt.get("error", content[:2000] or "MCP returned isError"),
        )


class MCPToolRegistry(ToolRegistry):
    """Resolve enabled servers dynamically, so disabling one revokes future calls."""

    def __init__(self, native, runtime):
        super().__init__()
        self.native, self.runtime = native, runtime

    def register(self, tool):
        self.native.register(tool)

    def mcp_tools(self):
        return [MCPAgentTool(self.runtime, server, tool) for server, tool in self.runtime.agent_tools()]

    def manifests(self):
        return self.native.manifests() + [tool.manifest for tool in self.mcp_tools()]

    def get(self, name):
        if not name.startswith("mcp:"):
            return self.native.get(name)
        for tool in self.mcp_tools():
            if tool.manifest.name == name:
                return tool
        raise ToolError("MCP 工具已禁用、连接配置已变更或工具尚未发现：" + name)
