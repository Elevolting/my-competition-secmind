"""Read-only execution search tools bound to the current task context."""
from __future__ import annotations

import asyncio

import jsonschema

from security_agent.schemas import RiskLevel, Scenario, ToolManifest, ToolResult, ToolStatus
from security_agent.tools import BaseTool


class TraceTool(BaseTool):
    def __init__(self, store, *, detail: bool = False):
        self.store, self.detail = store, detail
        properties = {"trace_id": {"type": "string", "minLength": 1, "maxLength": 200}} if detail else {
            "keyword": {"type": "string", "maxLength": 500},
            "worker": {"type": "string", "maxLength": 200},
            "module": {"type": "string", "maxLength": 50},
            "cursor": {"type": "integer", "minimum": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        }
        self.manifest = ToolManifest(
            name="get_worker_trace" if detail else "search_all_worker_traces", version="1.0",
            description="读取当前任务执行记录详情" if detail else "搜索当前任务其他 Worker 的公开执行记录",
            scenarios=list(Scenario),
            input_schema={"type": "object", "properties": properties,
                          "required": ["trace_id"] if detail else [], "additionalProperties": False},
            output_schema={"type": "object"}, risk_level=RiskLevel.R0,
            permissions=["ledger:read"], timeout_seconds=30, idempotent=True, requires_network=False,
        )

    async def invoke(self, args, context):
        try:
            jsonschema.validate(args, self.manifest.input_schema)
            if self.detail:
                data = await asyncio.to_thread(self.store.detail, context.run_id, args["trace_id"])
            else:
                data = await asyncio.to_thread(self.store.search, context.run_id, **args,
                    exclude_intent=context.blackboard.get("intent_id") if context.blackboard else None)
            return ToolResult(status=ToolStatus.SUCCESS, data=data, summary="已读取当前任务执行记录")
        except (KeyError, ValueError, jsonschema.ValidationError) as exc:
            return ToolResult(status=ToolStatus.ERROR, error_code="TRACE_UNAVAILABLE", error_message=str(exc))
