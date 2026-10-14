from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast
from urllib.parse import quote
from uuid import uuid4

import httpx
import jsonschema
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from security_agent.agents import (
    AnalystAgent,
    PlannerAgent,
    ReporterAgent,
    TaskInterpreterAgent,
    VerifierAgent,
)
from security_agent.blackboard_coordinator import BlackboardBinding, BlackboardCoordinator, BlackboardError
from security_agent.config import Settings
from security_agent.experience import ExperienceStore
from security_agent.fusion import classify_task
from security_agent.guardrail import GuardrailAction, GuardrailDecision
from security_agent.ingest import IngestError, InputIngestor
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelGateway
from security_agent.mcp_generated import GeneratedMCPStore
from security_agent.penetration_integration import (
    PenetrationProtocolError,
    assess_project_facts,
    project_title_for_run,
    wait_for_project_terminal,
)
from security_agent.report_sync import apply_penetration_evidence, confirmed_penetration_nodes
from security_agent.run_recovery import repeatable_call, transient_failure
from security_agent.schemas import (
    AgentState,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    BudgetState,
    DecisionRecord,
    KnowledgeHit,
    PlanningCallbackRequest,
    PlanningCallbackResponse,
    RiskLevel,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolContext,
    ToolResult,
    ToolStatus,
)
from security_agent.tools import ToolBroker, ToolError


class GraphState(TypedDict, total=False):
    agent: dict[str, Any]
    route: str


Publisher = Callable[[dict[str, Any]], Awaitable[None] | None]


class SecurityOrchestrator:
    def remaining_runtime_seconds(self, state: AgentState) -> float:
        """Return the run budget still available for an external poll.

        A module poll shorter than the remaining run budget would declare the
        task partial while the budget is still unspent, so callers cap the poll
        window with this value instead of the static configuration alone.
        """
        active_seconds = 0.0
        if state.active_node_started_at:
            started = state.active_node_started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            active_seconds = max(0.0, (datetime.now(UTC) - started).total_seconds())
        return max(0.0, state.budget.max_runtime_seconds - state.budget.runtime_seconds_used - active_seconds)

    def default_runtime_seconds(self, task: TaskRequest) -> int:
        if task.max_runtime_seconds is not None:
            return task.max_runtime_seconds
        routing = classify_task(task.objective, task.attachments, task.target_scope)
        if routing['scenario'] == Scenario.PENETRATION_TEST:
            return self.settings.penetration_max_runtime_seconds
        return self.settings.max_runtime_seconds

    def initial_budget(
        self, task: TaskRequest, *, max_runtime_seconds: int | None = None,
        max_tool_calls: int | None = None, max_model_calls: int | None = None,
    ) -> BudgetState:
        return BudgetState(
            max_steps=self.settings.max_steps,
            max_tool_calls=(
                max_tool_calls if max_tool_calls is not None else
                task.max_tool_calls if task.max_tool_calls is not None else self.settings.max_tool_calls
            ),
            max_model_calls=(
                max_model_calls if max_model_calls is not None else
                task.max_model_calls if task.max_model_calls is not None else (
                    self.settings.penetration_max_model_calls
                    if classify_task(task.objective, task.attachments, task.target_scope)['scenario'] == Scenario.PENETRATION_TEST
                    else self.settings.max_model_calls
                )
            ),
            max_runtime_seconds=(
                max_runtime_seconds if max_runtime_seconds is not None else self.default_runtime_seconds(task)
            ),
        )

    @staticmethod
    def _blackboard_plan_error(state: AgentState) -> str | None:
        if state.module_route != 'penetration' and state.scenario != Scenario.PENETRATION_TEST:
            if any(not step.tool_candidates for step in state.plan):
                return '每个执行步骤必须至少提供一个候选工具，才能由黑板意图调度'
            return None
        if len(state.plan) != 1 or state.plan[0].tool_candidates != ['penetration_module']:
            return '渗透任务必须通过黑板调度执行；请重试任务以生成黑板计划'
        return None

    @staticmethod
    def _next_node(name: str, route: str | None) -> str:
        if name == "execute" and route in {"report", "approval"}:
            return route
        conditional = {
            "classify": {"retrieve": "retrieve_context", "report": "report"},
            "validate_plan": {"select": "select_step", "report": "report"},
            "select_step": {"guardrail": "guardrail", "report": "report"},
            "guardrail": {"execute": "execute", "approval": "approval", "deny": "record_denial"},
            "approval": {"guardrail": "guardrail", "execute": "guardrail", "deny": "record_denial"},
            "verify": {"next": "select_step", "reflect": "reflect", "report": "report"},
            "plan": {"runtime_wait": "runtime_wait", "select": "validate_plan", "report": "report"},
        }
        if name in conditional:
            return conditional[name][route or ("select" if name == "plan" else "report")]
        return {
            "ingest": "classify", "classify": "retrieve_context", "retrieve_context": "plan",
            "plan": "validate_plan", "record_denial": "report", "execute": "observe",
            "runtime_wait": "report",
            "observe": "analyze", "analyze": "verify", "reflect": "select_step",
            "report": "memory_commit", "memory_commit": "end",
        }[name]

    @staticmethod
    def _charge_active_time(state: AgentState) -> None:
        if state.active_node_started_at is not None:
            started = state.active_node_started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            state.budget.runtime_seconds_used += max(0, (datetime.now(UTC) - started).total_seconds())
            state.active_node_started_at = None

    @staticmethod
    def _approval_digest(tool: str, parameters: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps([tool, parameters], sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    NODE_AGENTS = {
        "ingest": "interpreter",
        "classify": "interpreter",
        "retrieve_context": "interpreter",
        "plan": "planner",
        "runtime_wait": "analyst",
        "validate_plan": "planner",
        "select_step": "planner",
        "guardrail": "planner",
        "approval": "planner",
        "record_denial": "planner",
        "execute": "analyst",
        "observe": "analyst",
        "analyze": "analyst",
        "verify": "verifier",
        "reflect": "verifier",
        "report": "reporter",
        "memory_commit": "reporter",
    }
    NODE_INSTRUCTIONS = {
        "ingest": "固化输入材料并建立可追溯清单",
        "classify": "识别任务场景与授权边界",
        "retrieve_context": "检索完成任务所需的受控知识上下文",
        "plan": "生成有界、可验证的执行计划",
        "runtime_wait": "同步 Runtime 探索进度并等待工作台目标核验",
        "validate_plan": "校验计划依赖、预算与工具可用性",
        "select_step": "选择下一项满足依赖的执行步骤",
        "guardrail": "评估工具风险、策略与审批要求",
        "approval": "等待并处理操作员审批指令",
        "record_denial": "记录拒绝原因并安全终止当前步骤",
        "execute": "按照授权参数调用受控安全工具",
        "observe": "将工具结果规范化为运行观测",
        "analyze": "从观测中提取 Finding 与 Evidence",
        "verify": "验证发现与证据引用是否完整闭合",
        "reflect": "依据失败观测制定一次有界重试",
        "report": "汇总已验证事实并生成安全报告",
        "memory_commit": "评估本次运行是否可进入长期记忆候选",
    }
    def __init__(
        self,
        settings: Settings,
        ledger: LedgerStore,
        gateway: ModelGateway,
        broker: ToolBroker,
        publisher: Publisher | None = None,
        experiences: ExperienceStore | None = None,
        mcp_runtime=None,
    ) -> None:
        self.settings = settings
        self.ledger = ledger
        self.gateway = gateway
        self.broker = broker
        self.publisher = publisher
        self.experiences = experiences
        self.mcp_runtime = mcp_runtime
        self.blackboard = BlackboardCoordinator(settings, ledger)
        # A remote adapter can publish its run ID immediately before the
        # deadline cancels the graph. Keep that handoff in memory as well as
        # the Ledger so the cancellation request cannot lose the ID to a
        # concurrent state snapshot.
        self._live_external: dict[str, dict[str, Any]] = {}
        self._planning_locks: dict[str, asyncio.Lock] = {}
        self.ingestor = InputIngestor(settings)
        self.interpreter = TaskInterpreterAgent(gateway)
        self.planner = PlannerAgent(gateway, broker.registry)
        self.analyst = AnalystAgent(gateway, GeneratedMCPStore(settings.mcp_generated_root))
        self.verifier = VerifierAgent(gateway)
        self.reporter = ReporterAgent(gateway)
        self.checkpointer = InMemorySaver()
        self.graph = self._build_graph().compile(checkpointer=self.checkpointer)

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(GraphState)
        nodes = {
            "ingest": self._ingest,
            "classify": self._classify,
            "retrieve_context": self._retrieve_context,
            "plan": self._plan,
            "runtime_wait": self._runtime_wait,
            "validate_plan": self._validate_plan,
            "select_step": self._select_step,
            "guardrail": self._guardrail,
            "approval": self._approval,
            "record_denial": self._record_denial,
            "execute": self._execute,
            "observe": self._observe,
            "analyze": self._analyze,
            "verify": self._verify,
            "reflect": self._reflect,
            "report": self._report,
            "memory_commit": self._memory_commit,
        }
        for name, node in nodes.items():
            graph.add_node(name, cast(Any, self._instrument(name, node)))

        graph.add_conditional_edges(START, lambda value: value["agent"].get("resume_node") or "ingest",
                                    {**{name: name for name in nodes}, "end": END})
        graph.add_edge("ingest", "classify")
        graph.add_conditional_edges("classify", lambda value: value.get("route", "retrieve"),
                                    {"retrieve": "retrieve_context", "report": "report"})
        graph.add_edge("retrieve_context", "plan")
        graph.add_conditional_edges(
            "plan",
            lambda value: value.get("route", "select"),
            {"select": "validate_plan", "runtime_wait": "runtime_wait", "report": "report"},
        )
        graph.add_edge("runtime_wait", "report")
        graph.add_conditional_edges(
            "validate_plan",
            lambda value: value.get("route", "select"),
            {"select": "select_step", "report": "report"},
        )
        graph.add_conditional_edges(
            "select_step",
            lambda value: value.get("route", "guardrail"),
            {"guardrail": "guardrail", "report": "report"},
        )
        graph.add_conditional_edges(
            "guardrail",
            lambda value: value.get("route", "execute"),
            {"execute": "execute", "approval": "approval", "deny": "record_denial"},
        )
        graph.add_conditional_edges(
            "approval",
            lambda value: value.get("route", "guardrail"),
            {"guardrail": "guardrail", "deny": "record_denial"},
        )
        graph.add_edge("record_denial", "report")
        graph.add_conditional_edges("execute", lambda value: value["agent"].get("resume_node") or "observe",
                                    {"observe": "observe", "report": "report", "approval": "approval"})
        graph.add_edge("observe", "analyze")
        graph.add_edge("analyze", "verify")
        graph.add_conditional_edges(
            "verify",
            lambda value: value.get("route", "report"),
            {"next": "select_step", "reflect": "reflect", "report": "report"},
        )
        graph.add_edge("reflect", "select_step")
        graph.add_edge("report", "memory_commit")
        graph.add_edge("memory_commit", END)
        return graph

    def _instrument(self, name: str, node: Any) -> Any:
        async def instrumented(value: GraphState) -> GraphState:
            state = self._state(value)
            state.active_node = name
            state.resume_node = name
            state.active_node_started_at = datetime.now(UTC)
            self.ledger.save_state(state)
            value = {**value, "agent": state.model_dump(mode="json")}
            agent_id = self.NODE_AGENTS[name]
            instruction = self.NODE_INSTRUCTIONS[name]
            await self._event(
                state,
                "agent.started",
                {"agent_id": agent_id, "node": name, "instruction": instruction},
                actor=agent_id,
            )
            await self._event(
                state,
                "agent.instruction",
                {"agent_id": agent_id, "node": name, "content": instruction},
                actor="orchestrator",
            )
            decision_count = len(state.decisions)
            try:
                result = await node(value)
            except Exception as exc:
                await self._event(
                    state,
                    "agent.failed",
                    {"agent_id": agent_id, "node": name, "error_type": type(exc).__name__},
                    actor=agent_id,
                )
                raise
            next_state = self._state(result)
            if len(next_state.decisions) > decision_count:
                summary = next_state.decisions[-1].rationale_summary
            else:
                summary = self._public_summary(name, next_state)
            await self._event(
                next_state,
                "agent.thought",
                {"agent_id": agent_id, "node": name, "summary": summary},
                actor=agent_id,
            )
            await self._event(
                next_state,
                "agent.completed",
                {"agent_id": agent_id, "node": name, "status": next_state.status},
                actor=agent_id,
            )
            return result

        return instrumented

    @staticmethod
    def _public_summary(node: str, state: AgentState) -> str:
        summaries = {
            "ingest": f"已登记 {len(state.input_artifacts)} 个输入材料。",
            "validate_plan": "计划结构、依赖与预算校验已完成。",
            "select_step": f"当前执行步骤索引为 {state.current_step_index}。",
            "execute": f"受控工具调用累计 {state.budget.tool_calls_used} 次。",
            "observe": "工具输出已转换为可审计观测。",
            "analyze": f"已形成 {len(state.findings)} 个发现与 {len(state.evidence)} 条证据。",
            "verify": "发现与证据引用校验已完成。",
            "report": "报告已根据可验证事实生成。",
            "memory_commit": "记忆候选资格评估已完成。",
        }
        return summaries.get(node, "当前节点已完成可审计处理。")

    async def start(self, task: TaskRequest, run_id: str | None = None) -> AgentState:
        actual_run_id = run_id or str(uuid4())
        state = self.ledger.load_state(actual_run_id) or AgentState(
            run_id=actual_run_id,
            task=task,
            budget=self.initial_budget(task),
        )
        self.ledger.save_state(state)
        await self._event(state, "run.created", {"objective": task.objective})
        return await self._invoke({"agent": state.model_dump(mode="json")}, actual_run_id)

    async def planning_callback(self, request: PlanningCallbackRequest) -> PlanningCallbackResponse:
        lock = self._planning_locks.setdefault(request.run_id, asyncio.Lock())
        async with lock:
            return await self._planning_callback(request)

    async def _planning_callback(self, request: PlanningCallbackRequest) -> PlanningCallbackResponse:
        """Handle one authenticated Runtime reason callback.

        Runtime retries this request when a response is lost.  The decision ID
        is therefore persisted inside the run snapshot before the response is
        returned, making the operation safe across HTTP retries and workbench
        restarts.
        """
        state = self.ledger.load_state(request.run_id)
        if state is None:
            raise ValueError("运行不存在")
        board = state.external_execution.get("blackboard")
        if (not isinstance(board, dict) or board.get("project_id") != request.project_id
                or board.get("backend") != "remote"
                or board.get("planning_mode") != "workbench"
                or board.get("title") != f"sec-task-{request.run_id}"):
            raise ValueError("运行与黑板项目绑定不一致")
        if (request.goal != state.task.objective or request.module_route != state.module_route
                or request.target_scope != state.task.target_scope):
            raise ValueError("规划回调任务目标或授权范围与运行记录不一致")
        snapshot = {"facts": request.facts, "intents": request.intents, "hints": request.hints}
        snapshot['intents'] = [{k: v for k, v in i.items() if k != 'last_heartbeat_at'} for i in request.intents]
        snapshot_hash = hashlib.sha256(json.dumps(
            snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        if snapshot_hash != request.snapshot_hash:
            raise ValueError("规划回调的黑板快照校验失败")
        saved = state.external_execution.setdefault("planning_decisions", {})
        if not isinstance(saved, dict):
            saved = {}
            state.external_execution["planning_decisions"] = saved
        previous = saved.get(request.decision_id)
        if isinstance(previous, dict):
            replay = PlanningCallbackResponse.model_validate(previous)
            if replay.snapshot_hash != request.snapshot_hash:
                raise ValueError("规划决策 ID 已用于另一份黑板快照")
            return replay.model_copy(update={"replayed": True})

        if state.status in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}:
            return PlanningCallbackResponse(
                decision_id=request.decision_id, snapshot_hash=request.snapshot_hash,
                summary="任务已经进入终态，未派生新的验证想法。", stop_reason="任务已结束",
            )

        runtime_calls = self.mcp_runtime.store.blackboard_calls_used(state.run_id) if self.mcp_runtime else 0
        tool_limit = state.budget.max_tool_calls
        if self.settings.blackboard_max_mcp_calls_per_run is not None:
            tool_limit = min(tool_limit, self.settings.blackboard_max_mcp_calls_per_run)
        remaining_seconds = self.remaining_runtime_seconds(state)
        request = request.model_copy(update={"budget": {
            "execution_supported": request.budget.get("execution_supported", True),
            "max_new_intents": request.budget.get("max_new_intents", 3),
            "remaining_runtime_seconds": remaining_seconds,
            "remaining_model_calls": max(0, state.budget.max_model_calls - max(
                state.budget.model_calls_used, state.budget.provider_requests_used)),
            "remaining_tool_calls": max(0, tool_limit - runtime_calls),
            "runtime_tool_calls_used": runtime_calls,
        }})

        initial_budget = state.budget.model_copy(deep=True)

        async def observe_stream(event_type: str, payload: dict[str, Any]) -> None:
            await self._model_event(state, event_type, payload)

        tool_event_ids: set[str] = set()
        tool_receipts: dict[str, dict[str, Any]] = {}
        producing_intents = {item.get("id"): item for item in request.intents if isinstance(item, dict)}
        for event in self.ledger.events(state.run_id, limit=1_000_000):
            if event.event_type not in {"mcp.call.completed", "tool.completed"}:
                continue
            payload = event.payload
            binding = payload.get("blackboard")
            if not isinstance(binding, dict) or binding.get("project_id") != request.project_id:
                continue
            intent = producing_intents.get(binding.get("intent_id"))
            if (not intent or not intent.get("to") or intent.get("to") == "goal"
                    or not binding.get("attempt_id")
                    or binding.get("attempt_id") != intent.get("attempt_id")
                    or binding.get("worker") != intent.get("worker")
                    or not isinstance(payload.get("result"), dict)):
                continue
            call_id = payload.get("call_id")
            if isinstance(call_id, str) and call_id:
                tool_event_ids.add(call_id)
                tool_receipts[call_id] = {"fact_id": intent["to"], **payload}
            raw_result = payload["result"].get("structuredContent", {})
            evidence = raw_result.get("evidence", []) if isinstance(raw_result, dict) else []
            evidence_ids = list(payload.get("evidence_ids", [])) + [
                item.get("evidence_id") for item in evidence if isinstance(item, dict)]
            for evidence_id in evidence_ids:
                if isinstance(evidence_id, str) and evidence_id:
                    tool_event_ids.add(evidence_id)
                    tool_receipts[evidence_id] = {"fact_id": intent["to"], **payload}
        exhausted = next((label for key, label in (
            ("remaining_runtime_seconds", "任务总运行时间预算已耗尽"),
            ("remaining_model_calls", "模型调用预算已耗尽"),
            ("remaining_tool_calls", "Runtime 工具调用预算已耗尽"),
        ) if request.budget[key] <= 0), None)
        if request.budget['execution_supported'] is False:
            exhausted = '当前 Dispatcher 未配置支持任务预算的 Pi Worker，无法开始探索'
        open_intents = any(
            isinstance(intent, dict) and not intent.get('to') and not intent.get('concluded_at')
            and intent.get('execution_status') not in {'failed', 'timeout', 'cancelled'}
            for intent in request.intents
        )
        from security_agent.workbench_results import merge_workbench_results
        merge_workbench_results(state, request.facts, tool_receipts)
        linked_refs = list(dict.fromkeys(
            ref for fact in request.facts if isinstance(fact, dict)
            for item in (fact.get('items') if isinstance(fact.get('items'), list) else [])
            if isinstance(item, dict)
            for ref in (item.get('evidence_ids') or [])
            if isinstance(ref, str) and tool_receipts.get(ref, {}).get('fact_id') == fact.get('id')
        ))
        evidence_set = sorted(linked_refs)
        review = state.external_execution.get('goal_review', {})
        review_feedback = None
        known_fact_ids = {fact.get('id') for fact in request.facts if isinstance(fact, dict)}
        prior_goal_valid = bool(review.get('validated') and review.get('fact_ids')
                                and set(review['fact_ids']).issubset(known_fact_ids))
        if (linked_refs and review.get('evidence_ids') != evidence_set
                and not prior_goal_valid
                and request.budget['remaining_model_calls'] > 0
                and request.budget['remaining_runtime_seconds'] > 0):
            review_interrupted = False
            try:
                verified, reason, cited = await self.planner._validate_incremental_completion(
                    state, request, {str(fact['id']): fact for fact in request.facts
                                     if isinstance(fact, dict) and isinstance(fact.get('id'), str)},
                    linked_refs[-30:], '核验新增事实是否已满足原始任务目标',
                    observe_stream, tool_receipts,
                )
            except RuntimeError as exc:
                if str(exc) != '模型请求预算已耗尽':
                    raise
                verified, reason, cited = False, str(exc), set()
                exhausted = reason
                review_interrupted = True
            fact_ids = sorted({tool_receipts[ref]['fact_id'] for ref in cited}) if verified else []
            if not review_interrupted:
                review = {'evidence_ids': evidence_set, 'validated': verified,
                          'reason': reason, 'fact_ids': fact_ids}
                state.external_execution['goal_review'] = review
        if prior_goal_valid or (linked_refs and review.get('evidence_ids') == evidence_set):
            if review.get('validated'):
                response, meta = PlanningCallbackResponse(
                    decision_id=request.decision_id, snapshot_hash=request.snapshot_hash,
                    summary='现有工具回执已通过独立目标核验。',
                    completion_requested=True, completion_validated=True,
                    completion_reason=review['reason'], completion_fact_ids=review['fact_ids'],
                ), None
            else:
                review_feedback = review.get('reason') or '现有证据未证明目标已完成'
        goal_validated = bool(prior_goal_valid or (linked_refs and review.get('validated')
                              and review.get('evidence_ids') == evidence_set))
        if not goal_validated and exhausted:
            response, meta = PlanningCallbackResponse(
                decision_id=request.decision_id, snapshot_hash=request.snapshot_hash,
                summary="预算耗尽，保留当前事实、候选和证据。",
                stop_reason=(None if open_intents and request.budget['remaining_runtime_seconds'] > 0
                             and request.budget['execution_supported'] else exhausted)), None
        elif not goal_validated:
            try:
                response, meta = await self.planner.plan_incremental(
                    state, request, tool_event_ids, stream_observer=observe_stream,
                    tool_receipts=tool_receipts, completion_feedback=review_feedback,
                )
                await self.planner.verify_incremental_findings(state, observe_stream)
            except RuntimeError as exc:
                if str(exc) != '模型请求预算已耗尽':
                    raise
                response, meta = PlanningCallbackResponse(
                    decision_id=request.decision_id, snapshot_hash=request.snapshot_hash,
                    summary='模型预算耗尽，已保留本轮结果及证据。',
                    stop_reason=None if open_intents else str(exc)), None
        decision = DecisionRecord(
            decision="planning_round",
            rationale_summary=response.summary,
            evidence_ids=sorted(tool_event_ids)[:30],
            policy_ids=["PLANNER-INCREMENTAL-V1"],
            model_id=meta.model_id if meta else "deterministic-planner",
            prompt_version="incremental-plan-v1",
        )
        def merge_decision(current):
            current.external_execution.setdefault("planning_decisions", {})[request.decision_id] = response.model_dump(mode="json")
            current.decisions.append(decision)
            known_decisions = {(item.decision, tuple(item.policy_ids), tuple(item.evidence_ids))
                               for item in current.decisions}
            current.decisions.extend(item for item in state.decisions
                if (item.decision, tuple(item.policy_ids), tuple(item.evidence_ids)) not in known_decisions)
            merge_workbench_results(current, request.facts, tool_receipts)
            by_id = {item.finding_id: item for item in current.findings}
            by_id.update({item.finding_id: item for item in state.findings})
            current.findings = list(by_id.values())
            if 'goal_review' in state.external_execution:
                current.external_execution['goal_review'] = state.external_execution['goal_review']
            if response.completion_validated:
                current.external_execution['validated_goal_outputs'] = state.external_execution.get('validated_goal_outputs', [])
            if not state.external_execution.get('model_usage_via_events'):
                for field in ("model_calls_used", "prompt_tokens_used", "completion_tokens_used", "cache_read_tokens_used"):
                    setattr(current.budget, field, getattr(current.budget, field)
                            + max(0, getattr(state.budget, field) - getattr(initial_budget, field)))
            current.budget.model_usage_recorded |= state.budget.model_usage_recorded
        state = self.ledger.update_state(state.run_id, merge_decision)
        await self._event(state, "planning.decision", {
            "project_id": request.project_id,
            "decision_id": request.decision_id,
            "snapshot_hash": request.snapshot_hash,
            "trigger": request.trigger,
            "summary": response.summary,
            "intent_count": len(response.intents),
            "directions": [item.model_dump(mode="json", by_alias=True) for item in response.intents],
            "completion_requested": response.completion_requested,
            "completion_validated": response.completion_validated,
            "stop_reason": response.stop_reason,
            "budget": request.budget,
        }, actor="workbench_planner")
        return response

    async def resume(self, run_id: str, response: ApprovalResponse) -> AgentState:
        if self.mcp_runtime:
            await self.mcp_runtime.refresh_agent_tools()
        state = self.ledger.load_state(run_id)
        if state is None or state.status != RunStatus.WAITING_APPROVAL or state.pending_approval is None:
            raise ValueError("Approval request is not active")
        pending = state.pending_approval
        if pending.external:
            remote = pending.external
            endpoint = self.settings.reverse_base_url.rstrip('/') + '/api/v1/runs/' + quote(remote['remote_run_id'], safe='')
            endpoint += '/approvals/' + quote(remote['request_id'], safe='')
            headers = {'Authorization': 'Bearer ' + self.settings.secmind_operator_token} if self.settings.secmind_operator_token else {}
            async with httpx.AsyncClient(timeout=15, trust_env=False, headers=headers) as client:
                payload = response.model_dump(mode='json', exclude={'actor'})
                payload['resolution_id'] = pending.request_id
                reply = await client.post(endpoint, json=payload)
                reply.raise_for_status()
            state.approvals.append({'request_id': pending.request_id, 'step_id': pending.step_id,
                                    'external': remote, **response.model_dump(mode='json')})
            state.pending_approval = None
            state.active_node = None
            state.active_node_started_at = None
            state.status = RunStatus.DENIED if response.decision == ApprovalDecision.DENY else RunStatus.RUNNING
            state.resume_node = 'record_denial' if response.decision == ApprovalDecision.DENY else 'execute'
            state.external_execution['status'] = 'submitted'
            state.external_execution.setdefault('resolved_approval_ids', []).append(remote['request_id'])
            state.last_error = None
            self.ledger.save_state(state)
            await self._event(state, 'approval.resolved', {'external': remote, **response.model_dump(mode='json')})
            return await self._invoke({'agent': state.model_dump(mode='json')}, run_id)
        step = state.plan[state.current_step_index]
        if response.decision == ApprovalDecision.EDIT:
            if response.edited_parameters is None:
                raise ValueError("Edited parameters are required")
            step.inputs = response.edited_parameters
        state.approvals.append({"request_id": pending.request_id, "step_id": pending.step_id,
            "parameters_sha256": self._approval_digest(pending.tool_name, step.inputs),
            "risk_level": int(pending.risk_level),
            **response.model_dump(mode="json")})
        state.pending_approval = None
        state.active_node = None
        state.active_node_started_at = None  # Human review does not consume execution time.
        state.status = RunStatus.DENIED if response.decision == ApprovalDecision.DENY else RunStatus.RUNNING
        state.resume_node = "record_denial" if response.decision == ApprovalDecision.DENY else "guardrail"
        self.ledger.save_state(state)
        await self._event(state, "approval.resolved", response.model_dump(mode="json"))
        return await self._invoke({"agent": state.model_dump(mode="json")}, run_id)

    async def recover(self, run_id: str) -> AgentState:
        if self.mcp_runtime:
            await self.mcp_runtime.refresh_agent_tools()
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        if state.status == RunStatus.WAITING_APPROVAL:
            return state
        if state.status in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}:
            return state
        board = state.external_execution.get("blackboard")
        if (isinstance(board, dict) and board.get("planning_mode") == "workbench"
                and not state.plan):
            state.resume_node = "runtime_wait" if board.get("status") == "active" else "plan"
            state.active_node = None
            self.ledger.save_state(state)
            await self._event(state, "run.recovered", {"resume_node": state.resume_node})
            return await self._invoke({"agent": state.model_dump(mode="json")}, run_id)
        # Older durable snapshots could be written before the ingest node
        # published RUNNING.  Once recovery resumes at validation/execution,
        # promote that snapshot so blackboard leases can be validated.
        if state.status == RunStatus.PENDING and state.resume_node not in {None, "ingest"}:
            state.status = RunStatus.RUNNING
        self._charge_active_time(state)
        if state.active_node == "execute" and state.plan:
            try:
                step = state.plan[state.current_step_index]
                board = state.external_execution.get('blackboard')
                tool_name = board.get('scheduled_tool') if isinstance(board, dict) else None
                tool = self.broker.registry.get(
                    tool_name if isinstance(tool_name, str) else sorted(set(step.tool_candidates))[0]
                )
            except ToolError as exc:
                return await self._finish_partial(state, str(exc))
            if state.module_route == 'penetration':
                board = state.external_execution.get('blackboard')
                board_id = board.get('project_id') if isinstance(board, dict) else None
                saved_id = state.external_execution.get('project_id')
                if (not isinstance(board, dict) or board.get('backend') != 'remote'
                        or not isinstance(board_id, str) or not board_id
                        or saved_id and saved_id != board_id):
                    return await self._finish_partial(state, "渗透恢复项目与黑板绑定不一致，未继续执行。")
            if state.external_execution.get('project_id'):
                if not state.observations or state.observations[-1].data.get('project_id') != state.external_execution['project_id']:
                    state.observations.append(ToolResult(status=ToolStatus.SUCCESS, data={'project_id': state.external_execution['project_id']}))
                state.resume_node = 'verify'
            elif state.module_route == 'penetration' and state.external_execution.get('blackboard'):
                try:
                    project_status, dispatcher_enabled = await self.blackboard.penetration_dispatch_state(state)
                except BlackboardError as exc:
                    return await self._finish_partial(state, f"渗透黑板恢复核对失败：{exc}")
                project_id = state.external_execution['blackboard']['project_id']
                if dispatcher_enabled and project_status in {'active', 'completed'}:
                    state.external_execution.update(project_id=project_id, status='submitted')
                    state.observations.append(ToolResult(status=ToolStatus.SUCCESS, data={
                        'project_id': project_id, 'adapter': 'penetration_engine',
                    }))
                    state.resume_node = 'verify'
                elif not dispatcher_enabled and project_status == 'active':
                    if state.external_execution.get('status') == 'submitting':
                        state.external_execution['activation_retry'] = True
                    state.resume_node = 'execute'
                else:
                    return await self._finish_partial(state, "渗透黑板项目已停止或调度状态不一致，未重复执行。")
            else:
                try:
                    recovered_result = await self.blackboard.recover_conclusion(
                        state, state.plan[state.current_step_index],
                    )
                except BlackboardError as exc:
                    return await self._finish_partial(state, f"黑板工具结果恢复失败：{exc}")
                if recovered_result:
                    state.resume_node = 'observe'
                elif (not tool.manifest.idempotent or state.external_execution.get('status') == 'submitting') and not state.external_execution.get("remote_run_id"):
                    return await self._finish_partial(state, "服务中断时外部调用尚无完成回执，需核对外部任务；未自动重复执行。")
        if not state.resume_node:
            if state.status == RunStatus.PENDING:
                state.resume_node = "ingest"
            elif state.external_execution.get("project_id") and state.observations:
                state.resume_node = "verify"
            else:
                return await self._finish_partial(state, "旧版任务缺少可确定的恢复节点，已保留现有证据，未重复执行工具。")
        state.active_node = None
        self.ledger.save_state(state)
        await self._event(state, "run.recovered", {"resume_node": state.resume_node})
        return await self._invoke({"agent": state.model_dump(mode="json")}, run_id)

    async def _invoke(self, input_value: GraphState | Command, run_id: str) -> AgentState:
        state = self.ledger.load_state(run_id)
        assert state is not None
        remaining = state.budget.max_runtime_seconds - state.budget.runtime_seconds_used
        initial_seconds = state.budget.runtime_seconds_used
        invoked_at = time.monotonic()
        if remaining <= 0:
            await self._cancel_external(state)
            return await self._finish_partial(state, "任务运行时间预算已耗尽")
        timeout = asyncio.timeout(remaining)
        try:
            async with timeout:
                result = await self.graph.ainvoke(input_value,
                    {"configurable": {"thread_id": run_id}, "recursion_limit": max(50, self.settings.max_steps * 12)})
        except TimeoutError:
            if not timeout.expired():
                raise
            state = self.ledger.load_state(run_id) or state
            self._charge_active_time(state)
            state.budget.runtime_seconds_used = max(state.budget.runtime_seconds_used, initial_seconds + time.monotonic() - invoked_at)
            await self._event(state, "budget.exhausted", {"budget": "runtime"})
            await self._cancel_external(state)
            return await self._finish_partial(state, "任务运行时间预算已耗尽，已保留已完成步骤和证据")
        state = self._state(cast(GraphState, result))
        state.budget.runtime_seconds_used = max(state.budget.runtime_seconds_used, initial_seconds + time.monotonic() - invoked_at)
        if state.status == RunStatus.WAITING_APPROVAL:
            state.active_node = None
            state.active_node_started_at = None
        self.ledger.save_state(state)
        self._live_external.pop(run_id, None)
        return state

    async def _finish_partial(self, state: AgentState, reason: str) -> AgentState:
        state.status = RunStatus.PARTIAL
        state.last_error = reason
        await self.blackboard.stop(state, reason)
        state.active_node = None
        state.active_node_started_at = None
        state.resume_node = "end"
        state = await self.reporter.run(state, allow_model=False)
        self.ledger.save_state(state)
        await self._event(state, "report.generated", {"status": state.status, "reason": reason})
        await self._memory_commit({"agent": state.model_dump(mode="json")})
        self._live_external.pop(state.run_id, None)
        return state

    async def _cancel_external(self, state: AgentState) -> None:
        blackboard = state.external_execution.get('blackboard')
        if isinstance(blackboard, dict) and blackboard.get('status') in {'entered', 'active'}:
            await self.blackboard.stop(state, '统一任务取消或运行时预算耗尽')
            if state.module_route == 'penetration' and blackboard.get('status') in {'stopped', 'completed'}:
                state.external_execution['status'] = blackboard['status']
                return
        external = {**state.external_execution, **self._live_external.get(state.run_id, {})}
        state.external_execution = external
        if external.get('status') in {'completed', 'partial', 'failed', 'denied', 'cancelled', 'stopped'}:
            return
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                if external.get('remote_run_id'):
                    url = self.settings.reverse_base_url.rstrip('/') + '/api/v1/runs/' + quote(external['remote_run_id'], safe='') + '/cancel'
                    headers = {'Authorization': 'Bearer ' + self.settings.secmind_operator_token} if self.settings.secmind_operator_token else {}
                    reply = await client.post(url, headers=headers)
                elif external.get('project_id'):
                    url = self.settings.penetration_base_url.rstrip('/') + '/projects/' + quote(external['project_id'], safe='') + '/status'
                    reply = await client.put(url, json={'status': 'stopped'})
                else:
                    return
                reply.raise_for_status()
                receipt = reply.json()
                if external.get('remote_run_id'):
                    valid = (isinstance(receipt, dict)
                             and receipt.get('run_id') == external['remote_run_id']
                             and receipt.get('status') == 'cancelled')
                else:
                    valid = (isinstance(receipt, dict)
                             and receipt.get('id') == external['project_id']
                             and receipt.get('status') == 'stopped')
                if not valid:
                    raise ValueError('外部取消回执未确认目标任务')
            external['cancellation_requested'] = True
            await self._event(state, 'external.cancel.requested', {
                key: value for key, value in external.items() if key != 'blackboard'
            })
        except (httpx.HTTPError, ValueError) as exc:
            external['cancellation_error'] = type(exc).__name__
            await self._event(state, 'external.cancel.failed', {'error_type': type(exc).__name__})

    async def _model_event(self, state: AgentState, event_type: str, payload: dict[str, Any]) -> None:
        if (state.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench'
                and event_type in {'llm.stream.started', 'llm.stream.completed', 'llm.stream.failed'}):
            trace = payload.get('trace_id')
            def account(current):
                entries = current.external_execution.setdefault('workbench_model_requests', {})
                current.external_execution['model_usage_via_events'] = True
                entry = entries.get(trace)
                if event_type == 'llm.stream.started':
                    if entry:
                        return
                    if max(current.budget.provider_requests_used, current.budget.model_calls_used) >= current.budget.max_model_calls:
                        raise RuntimeError('模型请求预算已耗尽')
                    current.budget.provider_requests_used += 1
                    entries[trace] = {'status': 'reserved'}
                elif entry and entry['status'] == 'reserved':
                    usage = payload.get('usage') or {}
                    entry.update(status=event_type, usage=usage)
                    if event_type == 'llm.stream.completed':
                        current.budget.model_calls_used += 1
                    for key, field in (('prompt_tokens', 'prompt_tokens_used'),
                                       ('completion_tokens', 'completion_tokens_used'),
                                       ('cache_read_tokens', 'cache_read_tokens_used')):
                        setattr(current.budget, field, getattr(current.budget, field) + usage.get(key, 0))
                    current.budget.model_usage_recorded |= bool(usage)
            if not trace:
                raise RuntimeError('模型请求缺少关联 ID')
            updated = self.ledger.update_state(state.run_id, account)
            state.budget = updated.budget.model_copy(deep=True)
            state.external_execution['model_usage_via_events'] = True
            await self._event(state, event_type, payload, actor='llm_provider')
            return
        if event_type == "llm.stream.started":
            if state.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench':
                def reserve(current):
                    if max(current.budget.provider_requests_used, current.budget.model_calls_used) >= current.budget.max_model_calls:
                        raise RuntimeError('模型请求预算已耗尽')
                    current.budget.provider_requests_used += 1
                updated = self.ledger.update_state(state.run_id, reserve)
                state.budget.provider_requests_used = updated.budget.provider_requests_used
                await self._event(state, event_type, payload, actor='llm_provider')
                return
            if state.budget.provider_requests_used >= state.budget.max_model_calls:
                await self._event(state, "budget.exhausted", {"budget": "provider_requests"})
                raise RuntimeError("模型请求预算已耗尽")
            state.budget.provider_requests_used += 1
            self.ledger.save_state(state)
        await self._event(state, event_type, payload, actor="llm_provider")

    @staticmethod
    def _state(value: GraphState) -> AgentState:
        return AgentState.model_validate(value["agent"])

    async def _checkpoint(
        self, state: AgentState, event_type: str, payload: dict[str, Any], route: str | None = None
    ) -> GraphState:
        if state.active_node:
            state.resume_node = self._next_node(state.active_node, route)
            self._charge_active_time(state)
            state.active_node = None
        self.ledger.save_state(state)
        await self._event(state, event_type, payload)
        result: GraphState = {"agent": state.model_dump(mode="json")}
        if route is not None:
            result["route"] = route
        return result

    async def _event(
        self,
        state: AgentState,
        event_type: str,
        payload: dict[str, Any],
        actor: str = "system",
    ) -> None:
        event = self.ledger.append(state.run_id, event_type, payload, actor=actor)
        if self.publisher is not None:
            result = self.publisher(event.model_dump(mode="json"))
            if inspect.isawaitable(result):
                await result

    async def _ingest(self, value: GraphState) -> GraphState:
        state = self._state(value)
        state.status = RunStatus.RUNNING
        if not state.workspace:
            try:
                workspace, artifacts = self.ingestor.ingest(state.run_id, state.task.attachments)
                state.workspace = str(workspace)
                state.input_artifacts = artifacts
            except IngestError as exc:
                state.status = RunStatus.FAILED
                state.last_error = str(exc)
        return await self._checkpoint(
            state,
            "input.ingested",
            {
                "artifact_count": len(state.input_artifacts),
                "artifact_hashes": [item.sha256 for item in state.input_artifacts],
                "error": state.last_error,
            },
        )

    async def _classify(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.status == RunStatus.FAILED:
            return await self._checkpoint(state, "scenario.skipped", {"reason": state.last_error}, "report")
        async def observe_stream(event_type: str, payload: dict[str, Any]) -> None:
            await self._model_event(state, event_type, payload)

        state = await self.interpreter.run(state, stream_observer=observe_stream)
        route = "retrieve"
        try:
            await self.blackboard.enter(state)
        except BlackboardError as exc:
            state.status = RunStatus.FAILED
            state.last_error = str(exc)
            route = "report"
        return await self._checkpoint(state, "scenario.classified", {
            "scenario": state.scenario, "module": state.module_route, "routing": state.routing,
            "blackboard_error": state.last_error if route == "report" else None,
        }, route)

    async def _retrieve_context(self, value: GraphState) -> GraphState:
        state = self._state(value)
        records = self.experiences.search(state.module_route, state.task.objective, top_k=5, exclude_run_id=state.run_id) if self.experiences else []
        state.knowledge_hits = [
            KnowledgeHit(
                memory_id=item["experience_id"],
                content=self.experiences.context(item),
                source=item["source_title"],
                version=str(item["version"]),
                confidence=item["relevance_score"],
                metadata={
                    "kind": item["experience_kind"],
                    "module_route": item["module_route"],
                    "source_run_id": item["source_run_id"],
                    "relevance_score": item["relevance_score"],
                    "retrieval_reason": item["retrieval_reason"],
                },
            )
            for item in records
        ]
        state.decisions.append(
            DecisionRecord(
                decision="knowledge_context_retrieved" if records else "knowledge_context_empty",
                rationale_summary=(
                    f"已检索 {len(records)} 条同模块已审核相关经验，供规划节点参考。"
                    if records
                    else "当前经验库中没有可引用的同模块已审核相关经验。"
                ),
                policy_ids=["RAG-CITATION-V1"],
                model_id="deterministic-retriever",
            )
        )
        return await self._checkpoint(
            state,
            "knowledge.retrieved",
            {"hit_count": len(records), "experience_ids": [item["experience_id"] for item in records]},
        )

    async def _plan(self, value: GraphState) -> GraphState:
        state = self._state(value)
        runtime_owned = (
            not self.gateway.settings.demo_mode
            and bool(self.settings.security_runtime_callback_token)
            and state.module_route in {"penetration", "code_audit", "reverse"}
            and not state.plan
            and isinstance(state.external_execution.get("blackboard"), dict)
            and state.external_execution["blackboard"].get("planning_mode") == "workbench"
        )
        if runtime_owned:
            state.routing["execution_backend"] = "security_runtime"
            state.routing["runtime_owned"] = True
            state.routing["blackboard_required"] = True
            self.ledger.save_state(state)
            try:
                await self.blackboard.activate_runtime(state)
            except BlackboardError as exc:
                state.status = RunStatus.FAILED
                state.last_error = f"Runtime 接管失败：{exc}"
                return await self._checkpoint(state, "runtime.activation_failed", {"error": state.last_error}, "report")
            state = self.ledger.load_state(state.run_id) or state
            await self._event(state, "runtime.activated", {
                "project_id": state.external_execution.get("project_id"),
                "module": state.module_route,
            }, actor="blackboard_coordinator")
            return await self._checkpoint(state, "plan.delegated_to_runtime", {
                "project_id": state.external_execution.get("project_id"),
                "planner": "workbench.incremental",
            }, "runtime_wait")
        if (self.mcp_runtime and not self.gateway.settings.demo_mode
                and state.scenario != Scenario.PENETRATION_TEST):
            await self.mcp_runtime.refresh_agent_tools()
        if not state.plan:
            if self.experiences:
                # A review/edit may happen after retrieval. Never inject a revoked version.
                state.knowledge_hits = [hit for hit in state.knowledge_hits
                    if (current := self.experiences.get(hit.memory_id))
                    and current["review_status"] == "approved" and str(current["version"]) == hit.version]
            async def observe_stream(event_type: str, payload: dict[str, Any]) -> None:
                if event_type == "knowledge.planner_consumed" and self.experiences:
                    for hit in state.knowledge_hits:
                        self.experiences.record_use(state.run_id, hit, cited=hit.memory_id in payload.get("cited_ids", []), model_id=payload.get("model_id"))
                await self._model_event(state, event_type, payload)

            state = await self.planner.run(state, stream_observer=observe_stream)
        state.routing['execution_backend'] = (
            'mcp' if state.plan and all(
                step.tool_candidates and step.tool_candidates[0].startswith('mcp:') for step in state.plan
            ) else 'module'
        )
        # Tool execution is always mediated by a blackboard project and an
        # assigned intent.  Penetration projects are created by the external
        # module adapter; other modules are created lazily immediately before
        # their approved step executes.
        state.routing['blackboard_required'] = True
        return await self._checkpoint(
            state, "plan.created", {"steps": [item.model_dump(mode="json") for item in state.plan]}, "select"
        )

    async def _runtime_wait(self, value: GraphState) -> GraphState:
        """Wait for a Runtime-owned graph and project its durable result."""
        state = self._state(value)
        board = state.external_execution.get("blackboard")
        project_id = board.get("project_id") if isinstance(board, dict) else None
        if not isinstance(project_id, str) or not project_id:
            state.status = RunStatus.FAILED
            state.last_error = "Runtime 项目绑定缺失"
            return await self._checkpoint(state, "runtime.wait_failed", {"error": state.last_error}, "report")

        async def on_update(update: dict[str, Any]) -> None:
            nonlocal state
            # Runtime Workers and reason callbacks own parts of the same run
            # snapshot. Never write the polling node's original copy over it.
            state = self.ledger.load_state(state.run_id) or state
            await self.blackboard.sync_events_best_effort(state)
            state = self.ledger.load_state(state.run_id) or state
            progress = {"module": state.module_route, "project_id": project_id,
                        "runtime_status": update.get("status"),
                        "runtime_terminal": bool(update.get("terminal")),
                        "objective_reached": bool(update.get("objective_reached")),
                        "fact_count": update.get("fact_count"),
                        "intent_count": update.get("intent_count")}
            state = self.ledger.update_state(state.run_id, lambda current:
                current.external_execution.update(progress))
            await self._event(state, "runtime.progress", {
                key: update[key] for key in ("project_id", "status", "terminal", "objective_reached",
                                             "fact_count", "intent_count", "elapsed_ms") if key in update
            }, actor="security_runtime")

        try:
            external = await wait_for_project_terminal(
                self.settings.penetration_base_url, project_id,
                timeout_seconds=self.remaining_runtime_seconds(state),
                interval_seconds=self.settings.penetration_poll_interval_seconds,
                on_update=on_update,
            )
        except Exception as exc:
            state = self.ledger.load_state(state.run_id) or state
            state.status = RunStatus.PARTIAL
            state.last_error = f"Runtime 项目状态查询失败：{type(exc).__name__}"
            return await self._checkpoint(state, "runtime.wait_failed", {"error": state.last_error}, "report")

        state = self.ledger.load_state(state.run_id) or state
        detail = external.get("detail") if isinstance(external, dict) else None
        project = detail.get("project") if isinstance(detail, dict) else None
        if (not isinstance(project, dict) or project.get("id") != project_id
                or project.get("title") != project_title_for_run(state.run_id)):
            external = {**external, "objective_reached": False, "status": "identity_mismatch",
                        "error": "Runtime 项目身份与运行绑定不一致"}
        decisions = state.external_execution.get('planning_decisions', {}).values()
        stop_reason = next((d.get('stop_reason') for d in reversed(list(decisions)) if d.get('stop_reason')), None)
        if stop_reason and not external.get('objective_reached'):
            external['error'] = stop_reason
        available_evidence = {e.evidence_id for e in state.evidence}
        if external.get('objective_reached') and not any(
                d.decision == 'goal_verification_passed' and d.evidence_ids
                and set(d.evidence_ids).issubset(available_evidence) for d in state.decisions):
            external = {**external, 'objective_reached': False, 'error': 'Runtime 完成状态缺少工作台目标核验记录'}
        latest = ToolResult(
            status=(ToolStatus.SUCCESS if external.get("objective_reached") else
                    ToolStatus.TIMEOUT if external.get("status") == "timeout" else ToolStatus.ERROR),
            summary=f"Runtime {state.module_route} 项目完成：{external.get('status')}",
            data={"adapter": state.module_route, "project_id": project_id,
                  "external_project": detail.get("project") if isinstance(detail, dict) else None,
                  "external_facts": [item for item in detail.get("facts", [])
                                     if isinstance(item, dict)] if isinstance(detail, dict) else [],
                  "external_intents": [item for item in detail.get("intents", [])
                                       if isinstance(item, dict)] if isinstance(detail, dict) else [],
                  "external_status": external.get("status"),
                  "external_terminal": bool(external.get("terminal")),
                  "exploration_complete": bool(external.get("terminal")),
                  "external_fact_count": external.get("fact_count"),
                  "external_intent_count": external.get("intent_count"),
                  **{key: value for key, value in external.items() if key != "detail"}},
        )
        state.observations.append(latest)
        state.external_execution = {**state.external_execution, **latest.data}
        if isinstance(detail, dict):
            from security_agent.workbench_results import merge_workbench_results
            references = {ref: evidence.metadata['receipt'] for evidence in state.evidence
                          if isinstance(evidence.metadata.get('receipt'), dict)
                          for ref in [evidence.evidence_id]}
            merge_workbench_results(state, latest.data['external_facts'], references)
        if external.get("objective_reached"):
            state.status = RunStatus.COMPLETED
            state.last_error = None
        elif external.get("status") == "timeout":
            state.status = RunStatus.PARTIAL
            state.last_error = "Runtime 项目在运行时间预算内未完成"
        else:
            state.status = RunStatus.PARTIAL
            state.last_error = external.get("error") or "Runtime 已停止，目标尚未被可核验证据满足"
        return await self._checkpoint(state, "runtime.completed", {
            "project_id": project_id, "status": external.get("status"),
            "objective_reached": bool(external.get("objective_reached")),
            "fact_count": external.get("fact_count", 0),
            "intent_count": external.get("intent_count", 0),
        }, "report")

    async def _validate_plan(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.status == RunStatus.FAILED:
            return await self._checkpoint(state, "plan.skipped", {"reason": state.last_error}, "report")
        errors: list[str] = []
        if error := self._blackboard_plan_error(state):
            errors.append(error)
        identifiers = [step.step_id for step in state.plan]
        if len(identifiers) != len(set(identifiers)):
            errors.append("Plan step identifiers must be unique")
        if len(state.plan) > state.budget.max_steps:
            errors.append("Plan exceeds step budget")
        known_tools = {item.name for item in self.broker.registry.manifests()}
        for index, step in enumerate(state.plan):
            if not set(step.dependencies).issubset(set(identifiers[:index])):
                errors.append(f"Unknown dependency in {step.step_id}")
            if not set(step.tool_candidates).issubset(known_tools):
                errors.append(f"Unknown tool in {step.step_id}")
        if errors:
            state.status = RunStatus.FAILED
            state.last_error = "; ".join(errors)
        route = "select" if state.plan and not errors else "report"
        return await self._checkpoint(state, "plan.validated", {"errors": errors}, route)

    async def _select_step(self, value: GraphState) -> GraphState:
        state = self._state(value)
        while state.current_step_index < len(state.plan):
            step = state.plan[state.current_step_index]
            blocked = [dependency for dependency in step.dependencies if dependency in state.step_failures]
            if not blocked:
                break
            reason = "前置步骤未完成：" + ", ".join(blocked)
            state.step_failures[step.step_id] = reason
            state.current_step_index += 1
            await self._event(state, "step.skipped", {"step_id": step.step_id, "reason": reason})
        if state.current_step_index >= len(state.plan):
            return await self._checkpoint(state, "step.selection_complete", {}, "report")
        if state.budget.steps_used >= state.budget.max_steps:
            state.status = RunStatus.PARTIAL
            state.last_error = "执行步骤预算已耗尽"
            return await self._checkpoint(state, "budget.exhausted", {"budget": "steps"}, "report")
        step = state.plan[state.current_step_index]
        try:
            await self.blackboard.schedule(state, step)
        except BlackboardError as exc:
            state.status = RunStatus.FAILED
            state.last_error = str(exc)
            return await self._checkpoint(state, "blackboard.schedule_failed", {
                "step_id": step.step_id, "error": state.last_error,
            }, "report")
        state.budget.steps_used += 1
        return await self._checkpoint(
            state, "step.selected", {"step_id": step.step_id, "index": state.current_step_index}, "guardrail"
        )

    async def _guardrail(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if error := self._blackboard_plan_error(state):
            state.status = RunStatus.FAILED
            state.last_error = error
            return await self._checkpoint(state, 'guardrail.denied', {'reason': error}, 'deny')
        step = state.plan[state.current_step_index]
        if not step.tool_candidates:
            state.status = RunStatus.FAILED
            state.last_error = "所选执行步骤没有可用工具"
            return await self._checkpoint(state, "guardrail.denied", {"reason": state.last_error}, "deny")
        try:
            tool_name = await self.blackboard.authorize_tool(state, step)
        except BlackboardError as exc:
            state.status = RunStatus.FAILED
            state.last_error = str(exc)
            return await self._checkpoint(state, "blackboard.denied", {"error": state.last_error}, "deny")
        try:
            manifest = self.broker.registry.get(tool_name).manifest
            if tool_name.startswith('mcp:') and step.tool_version != manifest.version:
                raise ToolError('MCP 连接或工具协议已变更，请重新规划任务')
            decision = self.broker.assess(tool_name, step.inputs, state.task.autonomy_policy)
            jsonschema.validate(step.inputs, manifest.input_schema)
            if tool_name.startswith('mcp:'):
                from security_agent.mcp_agent import MCPAgentTool
                from security_agent.mcp_approval import offline_safe
                from security_agent.mcp_boundaries import AmbiguousMCPPathError, validate_workbench_arguments
                from security_agent.mcp_scope import target_values, validate_target_scope

                mcp_tool = self.broker.registry.get(tool_name)
                if isinstance(mcp_tool, MCPAgentTool):
                    exceptions = []
                    server_id = mcp_tool.server['server_id']
                    if state.task.network_policy == 'none' and not offline_safe(server_id, mcp_tool.tool['name']):
                        exceptions.append('任务未预先授权网络访问')
                    try:
                        validate_workbench_arguments(server_id, mcp_tool.tool['name'], step.inputs,
                                                     Path(state.workspace))
                    except AmbiguousMCPPathError as exc:
                        raise ToolError(str(exc)) from exc
                    except ValueError as exc:
                        exceptions.append(str(exc))
                    if not manifest.idempotent:
                        try:
                            validate_target_scope(server_id, step.inputs, state.task.target_scope)
                        except ValueError as exc:
                            if not target_values(step.inputs, server_id):
                                raise ToolError(str(exc)) from exc
                            exceptions.append(str(exc))
                    if exceptions:
                        decision = GuardrailDecision(GuardrailAction.REQUIRE_APPROVAL, RiskLevel.R3,
                            (*decision.policy_ids, 'POL-MCP-SCOPE-HITL'), '；'.join(dict.fromkeys(exceptions)))
        except (jsonschema.ValidationError, ToolError) as exc:
            state.status = RunStatus.FAILED
            state.last_error = f"工具校验失败：{exc}"
            return await self._checkpoint(state, "guardrail.denied", {"reason": state.last_error}, "deny")
        approved = next((item for item in reversed(state.approvals)
            if item.get('step_id') == step.step_id
            and item.get('parameters_sha256') == self._approval_digest(tool_name, step.inputs)
            and item.get('decision') in {ApprovalDecision.APPROVE.value, ApprovalDecision.EDIT.value}
            and int(item.get('risk_level', -1)) >= int(decision.risk_level)), None)
        state.decisions.append(
            DecisionRecord(
                decision=f"guardrail={decision.action.value}",
                rationale_summary=decision.reason,
                policy_ids=list(decision.policy_ids),
                model_id="deterministic-guardrail",
            )
        )
        if decision.action == GuardrailAction.DENY:
            state.status = RunStatus.DENIED
            route = "deny"
        elif decision.action == GuardrailAction.REQUIRE_APPROVAL and approved is None:
            state.status = RunStatus.WAITING_APPROVAL
            state.pending_approval = ApprovalRequest(
                run_id=state.run_id,
                step_id=step.step_id,
                tool_name=tool_name,
                parameters=step.inputs,
                target=str(step.inputs.get("target", state.workspace)),
                risk_level=decision.risk_level,
                reason=decision.reason,
                expected_impact=("调用已连接的 MCP 服务，可能访问桌面程序数据、修改目标状态或向原授权范围外发送请求。"
                                 if tool_name.startswith('mcp:') else "Execute one bounded tool call inside the controlled workspace."),
            )
            route = "approval"
        else:
            route = "execute"
        return await self._checkpoint(
            state,
            "guardrail.evaluated",
            {
                "step_id": step.step_id,
                "action": decision.action,
                "risk_level": decision.risk_level,
                "policy_ids": decision.policy_ids,
            },
            route,
        )

    async def _approval(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.pending_approval is None:
            state.status = RunStatus.FAILED
            state.last_error = "进入审批节点时不存在待处理的审批请求"
            return await self._checkpoint(state, "approval.invalid", {}, "deny")
        self.ledger.save_state(state)
        await self._event(state, "approval.requested", state.pending_approval.model_dump(mode="json"))
        raw_response = interrupt(state.pending_approval.model_dump(mode="json"))
        response = ApprovalResponse.model_validate(raw_response)
        pending = state.pending_approval
        state.approvals.append(
            {
                "request_id": pending.request_id,
                "step_id": pending.step_id,
                "parameters_sha256": self._approval_digest(pending.tool_name, response.edited_parameters if response.decision == ApprovalDecision.EDIT else pending.parameters),
                "risk_level": int(pending.risk_level),
                **response.model_dump(mode="json"),
            }
        )
        state.pending_approval = None
        if response.decision == ApprovalDecision.DENY:
            state.status = RunStatus.DENIED
            route = "deny"
        else:
            if response.decision == ApprovalDecision.EDIT and response.edited_parameters is not None:
                state.plan[state.current_step_index].inputs = response.edited_parameters
            state.status = RunStatus.RUNNING
            route = "guardrail"
        return await self._checkpoint(state, "approval.resolved", response.model_dump(mode="json"), route)

    async def _record_denial(self, value: GraphState) -> GraphState:
        state = self._state(value)
        if state.status != RunStatus.FAILED:
            state.status = RunStatus.DENIED
        return await self._checkpoint(
            state, "step.denied", {"step_index": state.current_step_index, "error": state.last_error}
        )

    async def _execute(self, value: GraphState) -> GraphState:
        state = self._state(value)
        # Durable resumes can enter execute without revisiting plan validation.
        if error := self._blackboard_plan_error(state):
            state.status = RunStatus.FAILED
            state.last_error = error
            return await self._checkpoint(state, 'tool.unavailable', {'error': error}, 'report')
        resuming = bool(state.external_execution.get('remote_run_id') or (
            state.module_route == 'penetration' and state.external_execution.get('activation_retry')
        ))
        if not resuming and state.budget.tool_calls_used >= state.budget.max_tool_calls:
            state.status = RunStatus.PARTIAL
            state.last_error = "工具调用预算已耗尽"
            return await self._checkpoint(state, "budget.exhausted", {"budget": "tools"}, "report")
        step = state.plan[state.current_step_index]
        binding: BlackboardBinding | None = None
        if state.module_route != 'penetration':
            try:
                binding = await self.blackboard.begin(state, step)
                tool_name = await self.blackboard.authorize_tool(state, step)
            except BlackboardError as exc:
                state.status = RunStatus.FAILED
                state.last_error = str(exc)
                return await self._checkpoint(
                    state, 'blackboard.denied', {'error': state.last_error, 'step_id': step.step_id}, 'report'
                )
        else:
            tool_name = step.tool_candidates[0]
        try:
            selected_tool = self.broker.registry.get(tool_name)
            if tool_name.startswith('mcp:') and selected_tool.manifest.version != step.tool_version:
                raise ToolError('MCP 连接或工具协议已变更，请重新规划任务')
        except ToolError as exc:
            state.status = RunStatus.FAILED
            state.last_error = str(exc)
            return await self._checkpoint(state, 'tool.unavailable', {'error': str(exc)}, 'report')
        if not resuming:
            state.budget.tool_calls_used += 1
        async def external_progress(update):
            current_blackboard = state.external_execution.get('blackboard')
            state.external_execution = {**state.external_execution, **update}
            if current_blackboard is not None:
                state.external_execution['blackboard'] = current_blackboard
            self._live_external[state.run_id] = dict(update)
            self.ledger.save_state(state)
            await self._event(state, 'external.status', update)
        backend = state.task.analysis_backend
        if backend == 'auto':
            backend = 'local' if self.settings.demo_mode else 'secmind'
        call_id = str(uuid4())
        if binding:
            state.external_execution['blackboard']['call_id'] = call_id
            self.ledger.save_state(state)
        await self._event(
            state,
            "tool.started",
            {
                "tool": tool_name,
                "call_id": call_id,
                "tool_version": selected_tool.manifest.version,
                "args": step.inputs,
                **({"blackboard": binding.as_dict()} if binding else {}),
            },
        )
        async def validate_blackboard() -> None:
            if binding is not None:
                await self.blackboard.validate(state, binding)

        context = ToolContext(
            run_id=state.run_id,
            step_id=step.step_id,
            workspace=state.workspace,
            allowed_paths=[state.workspace],
            module_base_url=(self.settings.penetration_base_url if state.module_route == 'penetration' else self.settings.reverse_base_url),
            analysis_backend=backend,
            module_auth_token=self.settings.secmind_operator_token,
            task_constraints=list(state.task.constraints),
            external_execution=dict(state.external_execution),
            blackboard=binding.as_dict() if binding else {},
            blackboard_validator=validate_blackboard if binding else None,
            progress_callback=external_progress,
            task_objective=state.task.objective,
            target_scope=list(state.task.target_scope),
            input_artifacts=list(state.input_artifacts),
            mcp_generated_root=str(self.settings.mcp_generated_root),
            module_poll_interval_seconds=self.settings.penetration_poll_interval_seconds,
            module_poll_timeout_seconds=self.settings.penetration_poll_timeout_seconds,
        )
        try:
            if binding is not None:
                async with self.blackboard.lease(state, binding):
                    result = await selected_tool.invoke(step.inputs, context)
            else:
                result = await selected_tool.invoke(step.inputs, context)
        except BlackboardError as exc:
            state.status = RunStatus.FAILED
            state.last_error = str(exc)
            return await self._checkpoint(
                state, 'blackboard.interrupted', {'error': state.last_error, 'step_id': step.step_id}, 'report'
            )
        state.observations.append(result)
        state.external_execution.pop('activation_retry', None)
        if binding is not None and result.error_code != 'REMOTE_APPROVAL_REQUIRED':
            try:
                await self.blackboard.conclude(state, binding, result)
            except BlackboardError as exc:
                state.status = RunStatus.PARTIAL
                state.last_error = f'工具结果未能写入黑板：{exc}'
                return await self._checkpoint(
                    state, 'blackboard.commit_failed', {'error': state.last_error, 'step_id': step.step_id}, 'report'
                )
        if result.error_code == 'REMOTE_APPROVAL_REQUIRED':
            approval = result.data['remote_approval']
            state.status = RunStatus.WAITING_APPROVAL
            state.pending_approval = ApprovalRequest(run_id=state.run_id, step_id=step.step_id,
                tool_name='secmind:' + str(approval.get('tool_name', 'tool')),
                parameters=approval.get('parameters', {}), target=str(approval.get('target', 'SecMind workspace')),
                risk_level=approval.get('risk_level', 2), reason=str(approval.get('reason', '分析引擎需要审批')),
                expected_impact=str(approval.get('expected_impact', '执行分析引擎的受控步骤')),
                external={'remote_run_id': result.data['remote_run_id'], 'request_id': approval['request_id']})
            return await self._checkpoint(state, 'external.approval.required', {'remote_run_id': result.data['remote_run_id']}, 'approval')
        if state.module_route == "penetration":
            project_id = result.data.get("project_id")
            if isinstance(project_id, str) and project_id.strip():
                state.external_execution = {**state.external_execution,
                    "module": "penetration",
                    "project_id": project_id.strip(),
                    "status": "submitted",
                    "objective_reached": False,
                }
        return await self._checkpoint(
            state,
            "tool.completed",
            {
                "tool": tool_name,
                "call_id": call_id,
                "fact_id": state.external_execution.get('blackboard', {}).get('fact_id') if binding else None,
                "status": result.status,
                "duration_ms": result.duration_ms,
                "evidence_ids": [item.evidence_id for item in result.evidence],
                "error_code": result.error_code,
                "error_message": result.error_message,
                "coverage": result.data.get("coverage"),
                "module_route": state.module_route,
                "project_id": result.data.get("project_id"),
                "external_status": state.external_execution.get("status"),
                **({"blackboard": binding.as_dict()} if binding else {}),
            },
        )

    async def _observe(self, value: GraphState) -> GraphState:
        state = self._state(value)
        latest = state.observations[-1]
        return await self._checkpoint(
            state, "observation.recorded", {"status": latest.status, "summary": latest.summary}
        )

    async def _analyze(self, value: GraphState) -> GraphState:
        state = self._state(value)
        async def observe_stream(event_type: str, payload: dict[str, Any]) -> None:
            await self._model_event(state, event_type, payload)

        state = await self.analyst.run(state, stream_observer=observe_stream)
        return await self._checkpoint(
            state,
            "analysis.completed",
            {"finding_count": len(state.findings), "evidence_count": len(state.evidence)},
        )

    async def _verify(self, value: GraphState) -> GraphState:
        state = await self.verifier.run(self._state(value))
        step = state.plan[state.current_step_index]
        latest = state.observations[-1]
        if state.module_route == "penetration":
            project_id = latest.data.get("project_id")
            if isinstance(project_id, str) and project_id.strip():
                board = state.external_execution.get('blackboard')
                if (not isinstance(board, dict) or board.get('backend') != 'remote'
                        or board.get('project_id') != project_id
                        or state.external_execution.get('project_id', project_id) != project_id):
                    latest.status = ToolStatus.ERROR
                    state.status = RunStatus.FAILED
                    state.last_error = '渗透验证项目与黑板绑定不一致'
                    return await self._checkpoint(state, 'penetration.identity_mismatch', {
                        'project_id': project_id,
                    }, 'report')
                async def on_update(update: dict[str, Any]) -> None:
                    await self.blackboard.sync_events_best_effort(state)
                    detail = update.get("detail")
                    if (isinstance(detail, dict) and isinstance(detail.get("project"), dict)
                            and detail["project"].get("id") == project_id):
                        assessments = state.external_execution.setdefault("fact_assessments", {})
                        async def assessment_event(event_type: str, payload: dict[str, Any]) -> None:
                            if event_type in {"llm.stream.started", "llm.stream.completed", "llm.stream.failed"}:
                                await self._model_event(state, event_type, payload)
                        await assess_project_facts(detail, assessments, self.gateway, assessment_event,
                            model_budget=min(2, max(0, state.budget.max_model_calls
                                - state.budget.provider_requests_used)))
                    # Publish terminal state only after the returned project
                    # identity and goal evidence have been checked below.
                    if update.get('terminal'):
                        return
                    update = {key: value for key, value in update.items() if key != "detail"}
                    state.external_execution = {**state.external_execution,
                        "module": "penetration",
                        **update,
                        "exploration_complete": bool(update.get("terminal")),
                    }
                    status_payload = {
                        key: update[key]
                        for key in (
                            "project_id", "status", "terminal", "objective_reached",
                            "fact_count", "intent_count", "goal_intent_count", "elapsed_ms",
                        )
                        if key in update
                    }
                    # Persist first so an event-driven UI refresh observes
                    # the same external_execution snapshot that produced the
                    # event, rather than racing the subsequent database write.
                    self.ledger.save_state(state)
                    await self._event(state, "penetration.status", status_payload)
                    # This explicit event is consumed by the UI as the
                    # exploration-path progress signal until the terminal
                    # decision below has been validated.
                    await self._event(state, "exploration.updated", status_payload)

                try:
                    external = await wait_for_project_terminal(
                        self.settings.penetration_base_url,
                        project_id.strip(),
                        timeout_seconds=min(
                            self.settings.penetration_poll_timeout_seconds,
                            self.remaining_runtime_seconds(state),
                        ),
                        interval_seconds=self.settings.penetration_poll_interval_seconds,
                        on_update=on_update,
                    )
                except Exception as exc:
                    latest.status = ToolStatus.ERROR
                    state.external_execution = {**state.external_execution,
                        "module": "penetration",
                        "project_id": project_id.strip(),
                        "status": "unavailable",
                        "terminal": True,
                        "exploration_complete": True,
                        "objective_reached": False,
                    }
                    state.status = RunStatus.PARTIAL
                    state.last_error = f"渗透外部项目状态查询失败：{type(exc).__name__}"
                    self.ledger.save_state(state)
                    await self._event(
                        state,
                        "exploration.completed",
                        {
                            "project_id": project_id,
                            "status": "unavailable",
                            "objective_reached": False,
                            "error": state.last_error,
                        },
                    )
                    return await self._checkpoint(
                        state,
                        "penetration.terminal",
                        {
                            "project_id": project_id,
                            "status": "unavailable",
                            "objective_reached": False,
                            "error": state.last_error,
                        },
                        "report",
                    )
                detail = external.get('detail')
                if external.get('status') == 'completed':
                    project = detail.get('project') if isinstance(detail, dict) else None
                    if (not isinstance(project, dict) or project.get('id') != project_id
                            or project.get('title') != project_title_for_run(state.run_id)):
                        external = {**external, 'status': 'identity_mismatch', 'failed': True,
                                    'objective_reached': False, 'detail': None}
                latest.data.update({
                    "external_status": external.get("status"),
                    "objective_reached": bool(external.get("objective_reached")),
                    "external_terminal": bool(external.get("terminal")),
                    "exploration_complete": bool(external.get("terminal")),
                    "external_fact_count": external.get("fact_count"),
                    "external_intent_count": external.get("intent_count"),
                })
                detail = external.get("detail")
                if isinstance(detail, dict):
                    # Preserve bounded blackboard content for the reporter so
                    # the final result can cite facts/flags instead of only
                    # showing project counters.
                    latest.data["external_project"] = detail.get("project")
                    latest.data["external_facts"] = [
                        item for item in detail.get("facts", [])[:200] if isinstance(item, dict)
                    ]
                    latest.data["external_intents"] = [
                        item for item in detail.get("intents", [])[:200] if isinstance(item, dict)
                    ]
                    # Sync the verified blackboard nodes into the run itself as
                    # soon as the project is terminal.  Without this the report
                    # was sealed with zero findings/evidence and the proof was
                    # only recoverable through a manual report refresh.
                    try:
                        confirmed = confirmed_penetration_nodes(
                            detail, state.external_execution.get("fact_assessments"))
                    except (PenetrationProtocolError, ValueError):
                        confirmed = []
                    if confirmed:
                        latest.data["verified_outputs"] = apply_penetration_evidence(
                            state, project_id.strip(), confirmed)
                state.external_execution = {**state.external_execution,
                    "module": "penetration",
                    "project_id": project_id.strip(),
                    "exploration_complete": bool(external.get("terminal")),
                    **{key: value for key, value in external.items() if key != "detail"},
                }
                if external.get("status") == "timeout":
                    latest.status = ToolStatus.TIMEOUT
                    state.status = RunStatus.PARTIAL
                    state.last_error = "渗透外部项目在限定时间内未进入终态"
                elif external.get("failed"):
                    latest.status = ToolStatus.ERROR
                    state.status = RunStatus.FAILED
                    state.last_error = f"渗透外部项目以 {external.get('status')} 终止"
                elif external.get("objective_reached"):
                    latest.status = ToolStatus.SUCCESS
                    state.last_error = None
                else:
                    latest.status = ToolStatus.ERROR
                    state.status = RunStatus.FAILED
                    state.last_error = "Security Runtime 已结束，但未提供可验证的目标完成证据"
                self.ledger.save_state(state)
                await self._event(state, "penetration.terminal", {
                    "project_id": project_id,
                    "status": state.external_execution.get("status"),
                    "objective_reached": state.external_execution.get("objective_reached", False),
                    "terminal": True,
                    "error": state.last_error,
                })
                await self._event(state, "exploration.completed", {
                    "project_id": project_id,
                    "status": state.external_execution.get("status"),
                    "objective_reached": state.external_execution.get("objective_reached", False),
                    "fact_count": state.external_execution.get("fact_count", 0),
                    "intent_count": state.external_execution.get("intent_count", 0),
                })
        if latest.status == ToolStatus.SUCCESS and state.last_error is None:
            state.current_step_index += 1
            route = "next" if state.current_step_index < len(state.plan) else "report"
        elif (
            state.status in {RunStatus.FAILED, RunStatus.DENIED}
            or state.external_execution.get("status") in {"timeout", "unavailable"}
        ):
            # A terminal external failure is not an idempotent tool error: do
            # not create a second Security Runtime project by sending the step through the
            # generic retry path.
            route = "report"
        else:
            attempts = state.retry_counts.get(step.step_id, 0)
            board = state.external_execution.get("blackboard")
            effective_tool_name = (
                board.get("scheduled_tool")
                if isinstance(board, dict) and isinstance(board.get("scheduled_tool"), str)
                else sorted(set(step.tool_candidates))[0]
            )
            try:
                manifest = self.broker.registry.get(effective_tool_name).manifest
                idempotent = repeatable_call(manifest, step.inputs)
            except ToolError:
                idempotent = False
            if (idempotent and transient_failure(latest) and not state.last_error
                    and not state.external_execution.get('remote_run_id')
                    and not state.external_execution.get('project_id')
                    and state.external_execution.get('status') != 'submitting'
                    and not latest.data.get("degraded") and attempts + 1 < step.max_attempts
                    and state.budget.steps_used < state.budget.max_steps
                    and state.budget.tool_calls_used < state.budget.max_tool_calls):
                route = "reflect"
            else:
                reason = state.last_error or latest.error_message or latest.summary or "工具未返回成功结果"
                state.step_failures[step.step_id] = reason[:3000]
                await self._event(state, "step.failed", {"step_id": step.step_id, "reason": reason[:3000]})
                # Only ordinary MCP tool failures may leave independent branches runnable.
                # Verification errors, denials and remote jobs always stop execution.
                if (effective_tool_name.startswith('mcp:')
                        and latest.status in {ToolStatus.ERROR, ToolStatus.TIMEOUT}
                        and not state.last_error
                        and not state.external_execution.get('remote_run_id')
                        and not state.external_execution.get('project_id')
                        and not latest.data.get('degraded')):
                    state.current_step_index += 1
                    route = "next"
                else:
                    state.last_error = reason[:3000]
                    if state.status not in {RunStatus.FAILED, RunStatus.DENIED}:
                        state.status = RunStatus.PARTIAL
                    route = "report"
        return await self._checkpoint(
            state,
            "verification.completed",
            {"step_id": step.step_id, "route": route, "error": state.last_error},
            route,
        )

    async def _reflect(self, value: GraphState) -> GraphState:
        state = self._state(value)
        step = state.plan[state.current_step_index]
        state.retry_counts[step.step_id] = state.retry_counts.get(step.step_id, 0) + 1
        state.last_error = None
        state.decisions.append(
            DecisionRecord(
                decision="retry_step",
                rationale_summary="受控工具调用失败，且仍有剩余重试次数。",
                policy_ids=["RETRY-IDEMPOTENT-V1"],
                model_id="deterministic-reflector",
            )
        )
        return await self._checkpoint(
            state, "reflection.completed", {"step_id": step.step_id, "retry": state.retry_counts[step.step_id]}
        )

    async def _report(self, value: GraphState) -> GraphState:
        state = self._state(value)
        async def observe_stream(event_type: str, payload: dict[str, Any]) -> None:
            await self._model_event(state, event_type, payload)

        state = await self.reporter.run(state, stream_observer=observe_stream)
        if state.external_execution.get('blackboard'):
            try:
                if state.status == RunStatus.COMPLETED:
                    await self.blackboard.complete(state)
                else:
                    await self.blackboard.stop(state, state.last_error or state.status.value)
            except BlackboardError as exc:
                # A report that cannot be sealed in the blackboard cannot be
                # advertised as a completed task. Preserve the report and
                # downgrade the run to a partial, auditable outcome.
                if state.status == RunStatus.COMPLETED:
                    state.status = RunStatus.PARTIAL
                    if state.report is not None:
                        state.report.status = RunStatus.PARTIAL
                        state.report.limitations.append("黑板终态未封存，不能证明任务已完成。")
                state.external_execution["blackboard"] = {
                    **state.external_execution.get("blackboard", {}),
                    "status": "finalize_failed",
                    "finalize_error": str(exc)[:1000] or type(exc).__name__,
                }
                state.last_error = f'黑板终态提交失败：{exc}'
                self.ledger.save_state(state)
                await self._event(state, 'blackboard.finalize_failed', {
                    'error_type': type(exc).__name__, 'project_id': state.external_execution.get('blackboard', {}).get('project_id'),
                })
        payload = {
            "status": state.status,
            "finding_count": len(state.findings),
            "evidence_count": len(state.evidence),
        }
        return await self._checkpoint(state, "report.generated", payload)

    async def _memory_commit(self, value: GraphState) -> GraphState:
        state = self._state(value)
        record = None
        error = None
        if self.experiences is not None:
            try:
                self.experiences.complete_uses(state)
                record = self.experiences.capture_run(
                    state,
                    self.ledger.events(state.run_id, limit=1_000_000),
                    chain_valid=self.ledger.verify(state.run_id),
                )
            except Exception as exc:
                error = f"经验写入失败：{type(exc).__name__}"
        accepted = record is not None
        payload = {
            "accepted": accepted,
            "experience_id": record["experience_id"] if record else None,
            "experience_kind": record["experience_kind"] if record else None,
            "reason": (
                "已提取、脱敏并写入结构化经验库。"
                if accepted
                else error or "当前任务状态不满足经验提取条件。"
            ),
        }
        return await self._checkpoint(state, "memory.candidate", payload)
