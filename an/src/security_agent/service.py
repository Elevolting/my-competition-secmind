from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from security_agent.bounded_http import CONSTRAINT as BOUNDED_HTTP_CONSTRAINT
from security_agent.bounded_http import POLICY as BOUNDED_HTTP_POLICY
from security_agent.ledger import LedgerStore
from security_agent.orchestrator import SecurityOrchestrator
from security_agent.run_recovery import retry_blocked_reason, stop_reason
from security_agent.schemas import (
    AgentState,
    ApprovalResponse,
    RunRetryRequest,
    RunStatus,
    RunSummary,
    TaskRequest,
)
from security_agent.scoped_file_post import CONSTRAINT as SCOPED_POST_CONSTRAINT
from security_agent.scoped_file_post import POLICY as SCOPED_POST_POLICY
from security_agent.scoped_file_post import load_grant, scope_matches_grant
from security_agent.session_http import CONSTRAINT as SESSION_HTTP_CONSTRAINT
from security_agent.session_http import POLICY as SESSION_HTTP_POLICY

LOG = logging.getLogger(__name__)


def canonical_module_route(value: str | None, scenario: str | None = None) -> str:
    """Normalize legacy route names before exposing RunSummary to clients."""
    candidate = str(value or scenario or "code_audit").strip().lower()
    scenario_value = str(scenario or "").strip().lower()
    if candidate == "audit" and scenario_value in {"reverse_triage", "penetration_test", "reverse", "penetration"}:
        candidate = scenario_value
    return {"audit": "code_audit", "reverse_triage": "reverse", "penetration_test": "penetration"}.get(candidate, candidate)


class EventHub:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._all_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers.get(str(event["run_id"]), ()))
            all_subscribers = tuple(self._all_subscribers)
        for queue in (*subscribers, *all_subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self, run_id: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers[run_id].add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers[run_id].discard(queue)

    @asynccontextmanager
    async def subscribe_all(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._all_subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._all_subscribers.discard(queue)


class RunService:
    def __init__(self, orchestrator: SecurityOrchestrator, ledger: LedgerStore, event_hub: EventHub) -> None:
        self.orchestrator = orchestrator
        self.ledger = ledger
        self.event_hub = event_hub
        self._tasks: set[asyncio.Task[Any]] = set()
        self._run_tasks: dict[str, asyncio.Task[Any]] = {}
        self._run_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._cancel_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._approval_inflight: set[str] = set()

    def submit(self, task: TaskRequest, *, run_id: str | None = None,
               retry_of: str | None = None, retry_context: dict | None = None,
               max_runtime_seconds: int | None = None, max_tool_calls: int | None = None,
               max_model_calls: int | None = None) -> str:
        from security_agent.target_urls import normalize_target_url

        run_id = run_id or str(uuid4())
        existing = self.ledger.load_state(run_id)
        if existing is not None:
            if existing.task != task:
                raise ValueError("run_id 已绑定另一项任务，拒绝覆盖运行记录")
            for field, value in {"max_runtime_seconds": max_runtime_seconds,
                                 "max_tool_calls": max_tool_calls, "max_model_calls": max_model_calls}.items():
                if value is not None and getattr(existing.budget, field) != value:
                    raise ValueError("run_id 已绑定不同的任务预算，拒绝覆盖运行记录")
            # A retry reads the recorded task and never depends on an upload
            # reference remaining available after the original submission.
            return run_id
        scoped_urls = {normalize_target_url(value) for value in task.target_scope
                       if '://' in value or value.lower().startswith(('http:', 'https:'))}
        for attachment in task.attachments:
            if not (attachment.name or attachment.ref).lower().endswith('.url'):
                continue
            source = self.orchestrator.ingestor._resolve_reference(attachment.ref)
            if source.is_symlink() or not source.is_file() or source.stat().st_size > 8192:
                raise ValueError("URL 材料不存在或超过 8 KB")
            content = source.read_text(encoding="utf-8-sig").strip()
            if content.startswith("[InternetShortcut]"):
                content = next((line[4:].strip() for line in content.splitlines()
                                if line.startswith("URL=")), "")
            material_url = normalize_target_url(content)
            if material_url not in scoped_urls:
                raise ValueError("URL 材料与任务授权范围不一致")
        if task.network_policy == SCOPED_POST_POLICY:
            grant = load_grant(self.orchestrator.settings)
            if (grant is None or retry_of != grant.source_run_id
                    or run_id != grant.child_run_id or not scope_matches_grant(task.target_scope, grant)):
                raise ValueError("此受限 POST 策略仅允许已授权的单次重试")
        state = AgentState(
            run_id=run_id,
            task=task,
            status=RunStatus.PENDING,
            retry_of=retry_of,
            retry_context=retry_context or {},
            budget=self.orchestrator.initial_budget(task, max_runtime_seconds=max_runtime_seconds,
                max_tool_calls=max_tool_calls, max_model_calls=max_model_calls),
        )
        self.ledger.save_state(state)
        self.ledger.append(
            run_id,
            "run.queued",
            {"name": task.name, "objective": task.objective, "budget": state.budget.model_dump(mode="json")},
            actor="api",
        )
        self._spawn(self._start(task, run_id))
        return run_id

    def retry(self, run_id: str, request: RunRetryRequest) -> str:
        source = self.state(run_id)
        retry_parameters = request.model_dump(mode="json", exclude={"request_id"})
        def same_retry(child: AgentState) -> bool:
            saved = child.retry_context.get("retry_parameters")
            if saved is not None:
                # Older request snapshots lack the optional call budgets.
                return {key: saved.get(key) for key in retry_parameters} == retry_parameters
            # Older retries lack the request snapshot; check their effective
            # authorization and any explicitly requested runtime instead.
            return (child.task.network_policy == (request.network_policy or source.task.network_policy)
                    and (request.max_runtime_seconds is None
                         or child.budget.max_runtime_seconds == request.max_runtime_seconds)
                    and (request.max_tool_calls is None or child.budget.max_tool_calls == request.max_tool_calls)
                    and (request.max_model_calls is None or child.budget.max_model_calls == request.max_model_calls))
        child_id = str(uuid5(NAMESPACE_URL, f"run-retry:{run_id}:{request.request_id}"))
        existing = self.ledger.load_state(child_id)
        if existing is not None:
            if not same_retry(existing):
                raise ValueError("重试请求已绑定不同的运行时限或网络策略或调用预算")
            return child_id  # Network retries remain idempotent across API restarts.
        reason = retry_blocked_reason(source)
        if reason:
            raise ValueError(reason)
        for state in self.ledger.list_states(limit=None):
            if state.retry_of == run_id and state.status in {
                RunStatus.PENDING, RunStatus.RUNNING, RunStatus.WAITING_APPROVAL,
            }:
                if not same_retry(state):
                    raise ValueError("已有执行中的重试，且运行时限或网络策略不同，或调用预算不同")
                return state.run_id
        context = {
            "retry_parameters": retry_parameters,
            "stop_reason": stop_reason(source),
            "previous_runtime_seconds": source.budget.max_runtime_seconds,
            "previous_budget": source.budget.model_dump(mode="json"),
            "failed_steps": source.step_failures,
            "failed_observations": [
                {"error": item.error_message or item.summary, "code": item.error_code}
                for item in source.observations if item.status.value != "success"
            ][-5:],
        }
        task = source.task.model_copy(deep=True)
        if request.network_policy == SCOPED_POST_POLICY:
            grant = load_grant(self.orchestrator.settings)
            if (grant is None or run_id != grant.source_run_id
                    or request.request_id != grant.request_id
                    or source.module_route != "penetration"
                    or not scope_matches_grant(task.target_scope, grant)
                    or task.network_policy != "read_only_http"):
                raise ValueError("此受限 POST 授权不适用于当前重试")
            prior = next((item for item in source.findings
                          if item.rule_id == "PENETRATION-CONFIRMED-RESULT"
                          and item.evidence_ids), None)
            if prior:
                context["prior_blackboard_fact"] = {
                    "source_project_id": source.external_execution.get("project_id"),
                    "description": prior.description[:1800],
                    "evidence_ids": prior.evidence_ids[:5],
                }
        if request.network_policy is not None:
            if request.network_policy in {"read_only_http", BOUNDED_HTTP_POLICY, SESSION_HTTP_POLICY} and (
                source.module_route != "penetration" or not any(
                    target.startswith(("http://", "https://")) for target in task.target_scope
                )
            ):
                raise ValueError("HTTP 授权探测仅适用于有授权 URL 的渗透任务")
            task.network_policy = request.network_policy
            task.constraints = [
                constraint for constraint in task.constraints
                if constraint not in {
                    "仅允许只读静态分析",
                    "仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转",
                    SCOPED_POST_CONSTRAINT,
                    BOUNDED_HTTP_CONSTRAINT,
                    SESSION_HTTP_CONSTRAINT,
                }
            ]
            task.constraints.append(
                SCOPED_POST_CONSTRAINT if request.network_policy == SCOPED_POST_POLICY else
                SESSION_HTTP_CONSTRAINT if request.network_policy == SESSION_HTTP_POLICY else
                BOUNDED_HTTP_CONSTRAINT if request.network_policy == BOUNDED_HTTP_POLICY else
                "仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转"
                if request.network_policy == "read_only_http" else "仅允许只读静态分析"
            )
        runtime_seconds = request.max_runtime_seconds or (
            self.orchestrator.settings.penetration_max_runtime_seconds
            if source.module_route == "penetration" else None
        )
        child_id = self.submit(
            task, run_id=child_id,
            retry_of=run_id, retry_context=context, max_runtime_seconds=runtime_seconds,
            max_tool_calls=(
                request.max_tool_calls if request.max_tool_calls is not None else source.budget.max_tool_calls
            ),
            max_model_calls=(
                request.max_model_calls if request.max_model_calls is not None else source.budget.max_model_calls
            ),
        )
        self.ledger.append(child_id, "run.retry_created", {"retry_of": run_id}, actor="api")
        return child_id

    def run_lock(self, run_id: str) -> asyncio.Lock:
        return self._run_locks[run_id]

    async def _start(self, task: TaskRequest, run_id: str, *, recover: bool = False,
                     approval: ApprovalResponse | None = None) -> None:
        if approval is None:
            existing = self.ledger.load_state(run_id)
            if existing is not None and existing.status in {
                RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED,
            }:
                return
        current_task = asyncio.current_task()
        if current_task is not None:
            self._run_tasks[run_id] = current_task
        try:
            async with self._run_locks[run_id]:
                current = self.ledger.load_state(run_id)
                if current is not None and current.status in {
                    RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED,
                }:
                    return
                if approval is not None:
                    await self.orchestrator.resume(run_id, approval)
                elif recover:
                    await self.orchestrator.recover(run_id)
                else:
                    await self.orchestrator.start(task, run_id)
        except Exception as exc:
            state = self.ledger.load_state(run_id)
            if approval is not None and state is not None and state.pending_approval is not None:
                # The remote decision may be unavailable or its acknowledgement
                # may have been lost. Preserve the request so the operator can
                # retry against the engine's idempotent approval endpoint.
                state.last_error = f"审批暂未完成：{type(exc).__name__}"
                self.ledger.save_state(state)
                event = self.ledger.append(run_id, "approval.failed", {"error": state.last_error}, actor="orchestrator")
                await self.event_hub.publish(event.model_dump(mode="json"))
                return
            if state is not None:
                state.status = RunStatus.FAILED
                state.last_error = f"{type(exc).__name__}: {exc}"
                try:
                    await self.orchestrator.blackboard.stop(state, state.last_error)
                except Exception as stop_error:
                    # The original failure remains authoritative; stop failure
                    # is recorded by the coordinator and must not mask it.
                    LOG.exception(
                        "failed to stop blackboard after task failure run_id=%s error_type=%s",
                        run_id,
                        type(stop_error).__name__,
                    )
                self.ledger.save_state(state)
                event = self.ledger.append(run_id, "run.failed", {"error": state.last_error}, actor="orchestrator")
                await self.event_hub.publish(event.model_dump(mode="json"))
                if self.orchestrator.experiences:
                    try:
                        self.orchestrator.experiences.complete_uses(state)
                        record = self.orchestrator.experiences.capture_run(state, self.ledger.events(run_id, limit=1_000_000), chain_valid=self.ledger.verify(run_id))
                        learned = self.ledger.append(run_id, "memory.candidate", {"experience_id": record["experience_id"] if record else None}, actor="experience_learner")
                        await self.event_hub.publish(learned.model_dump(mode="json"))
                    except Exception as learning_error:
                        self.ledger.append(run_id, "memory.failed", {"error_type": type(learning_error).__name__}, actor="experience_learner")
        finally:
            if current_task is not None and self._run_tasks.get(run_id) is current_task:
                self._run_tasks.pop(run_id, None)
            if approval is not None:
                self._approval_inflight.discard(run_id)

    def submit_approval(self, run_id: str, response: ApprovalResponse) -> None:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        if run_id in self._approval_inflight or state.pending_approval is None or state.status != RunStatus.WAITING_APPROVAL:
            raise ValueError("Approval request is no longer available or is being processed")
        self._approval_inflight.add(run_id)
        self._spawn(self._start(state.task, run_id, approval=response))

    async def cancel(self, run_id: str, reason: str = "用户请求取消任务") -> AgentState:
        async with self._cancel_locks[run_id]:
            state = self.ledger.load_state(run_id)
            if state is None:
                raise KeyError(run_id)
            if state.status in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.DENIED}:
                return state
            state.status = RunStatus.PARTIAL
            state.last_error = reason[:2000]
            state.pending_approval = None
            self.ledger.save_state(state)
            task = self._run_tasks.get(run_id)
            if task is not None and not task.done() and task is not asyncio.current_task():
                task.cancel()
            event = self.ledger.append(run_id, "run.cancel.requested", {"reason": reason[:1000]}, actor="api")
            await self.event_hub.publish(event.model_dump(mode="json"))
            await self.orchestrator._cancel_external(state)
            external = state.external_execution
            if external.get("remote_run_id") or external.get("project_id"):
                board = external.get("blackboard")
                if (state.module_route == "penetration" and isinstance(board, dict)
                        and board.get("project_id") == external.get("project_id")
                        and board.get("status") in {"stopped", "completed"}):
                    external["status"] = board["status"]
                elif external.get("cancellation_requested"):
                    external["status"] = "cancellation_requested"
                elif external.get("cancellation_error"):
                    external["status"] = "cancellation_unconfirmed"
            else:
                external["status"] = "cancelled"
            state = await self.orchestrator._finish_partial(state, reason)
            return state

    def state(self, run_id: str) -> AgentState:
        state = self.ledger.load_state(run_id)
        if state is None:
            raise KeyError(run_id)
        return state

    def summary(self, run_id: str) -> RunSummary:
        state = self.state(run_id)
        public_external = {key: value for key, value in state.external_execution.items() if key != "blackboard"}
        return RunSummary(
            run_id=run_id,
            name=state.task.name,
            status=state.status,
            scenario=state.scenario,
            module_route=canonical_module_route(state.module_route, state.scenario.value),
            routing=state.routing,
            current_step=self._completed_steps(state),
            total_steps=len(state.plan),
            input_artifact_count=len(state.input_artifacts),
            pending_approval=state.pending_approval,
            last_error=state.last_error,
            **self._recovery_summary(state),
            external_execution=public_external,
            blackboard={key: value for key, value in state.external_execution.get("blackboard", {}).items()
                        if key != "activation_token"},
            budget=state.budget,
        )

    def summaries(self, limit: int = 100, offset: int = 0,
                  before: tuple[datetime, str] | None = None) -> list[RunSummary]:
        return [
            RunSummary(
                run_id=state.run_id,
                name=state.task.name,
                status=state.status,
                scenario=state.scenario,
                module_route=canonical_module_route(state.module_route, state.scenario.value),
                routing=state.routing,
                current_step=self._completed_steps(state),
                total_steps=len(state.plan),
                input_artifact_count=len(state.input_artifacts),
                pending_approval=state.pending_approval,
                last_error=state.last_error,
                **self._recovery_summary(state),
                external_execution={key: value for key, value in state.external_execution.items() if key != "blackboard"},
                blackboard={key: value for key, value in state.external_execution.get("blackboard", {}).items()
                            if key != "activation_token"},
                budget=state.budget,
            )
            for state in self.ledger.list_states(limit, offset, before)
        ]

    @staticmethod
    def _completed_steps(state: AgentState) -> int:
        return sum(step.step_id not in state.step_failures for step in state.plan[:state.current_step_index])

    @staticmethod
    def _recovery_summary(state: AgentState) -> dict:
        blocked = retry_blocked_reason(state)
        return {"stop_reason": stop_reason(state), "can_retry": blocked is None,
                "retry_blocked_reason": blocked, "retry_of": state.retry_of}

    async def recover_incomplete(self) -> None:
        for run_id in self.ledger.incomplete_run_ids():
            state = self.ledger.load_state(run_id)
            if state and state.status != RunStatus.WAITING_APPROVAL:
                self._spawn(self._start(state.task, run_id, recover=True))

    async def shutdown(self) -> None:
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
