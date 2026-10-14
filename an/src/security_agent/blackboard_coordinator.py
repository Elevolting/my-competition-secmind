"""Durable blackboard coordination for every unified-workbench task.

The Security Runtime is the authoritative blackboard in a live deployment.  A
small local implementation is kept for demo/offline runs so those runs still
exercise the same project, intent, lease and completion invariants instead of
silently taking a direct-tool shortcut.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx

from security_agent.bounded_http import POLICY as BOUNDED_HTTP_POLICY
from security_agent.penetration_integration import project_title_for_run
from security_agent.schemas import AgentState, PlanStep, RunStatus, Scenario, ToolResult, ToolStatus
from security_agent.scoped_file_post import POLICY as SCOPED_POST_POLICY
from security_agent.session_http import POLICY as SESSION_HTTP_POLICY


class BlackboardError(RuntimeError):
    """The task cannot safely continue without its blackboard assignment."""


@dataclass(frozen=True)
class BlackboardBinding:
    backend: str
    project_id: str
    intent_id: str
    worker: str
    step_id: str
    fact_id: str | None = None
    attempt_id: str | None = None
    source_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "project_id": self.project_id,
            "intent_id": self.intent_id,
            "worker": self.worker,
            "step_id": self.step_id,
            "fact_id": self.fact_id,
            "attempt_id": self.attempt_id,
            "source_ids": list(self.source_ids),
        }

    @classmethod
    def from_state(cls, value: Any) -> BlackboardBinding | None:
        if not isinstance(value, dict):
            return None
        required = ("backend", "project_id", "intent_id", "worker", "step_id")
        if not all(isinstance(value.get(key), str) and value[key].strip() for key in required):
            return None
        if value["backend"] not in {"local", "remote"}:
            return None
        fact_id = value.get("fact_id")
        if fact_id is not None and (not isinstance(fact_id, str) or not fact_id.strip()):
            return None
        return cls(
            backend=value["backend"], project_id=value["project_id"],
            intent_id=value["intent_id"], worker=value["worker"],
            step_id=value["step_id"], fact_id=fact_id,
            attempt_id=value.get("attempt_id") if isinstance(value.get("attempt_id"), str) else None,
            source_ids=tuple(item for item in value.get("source_ids", []) if isinstance(item, str))
            if isinstance(value.get("source_ids", []), list) else (),
        )


class BlackboardCoordinator:
    """Create, lease and close one blackboard intent for each tool step."""

    def __init__(self, settings, ledger) -> None:
        self.settings = settings
        self.ledger = ledger
        self.base_url = str(settings.penetration_base_url).rstrip("/")
        self.heartbeat_interval_seconds = 10.0
        self._event_locks: dict[str, asyncio.Lock] = {}

    @property
    def local_mode(self) -> bool:
        # Demo mode deliberately uses a durable-in-state blackboard.  It keeps
        # tests and offline installations honest without pretending a remote
        # Security Runtime is available.
        return bool(getattr(self.settings, "demo_mode", False))

    @staticmethod
    def worker_for(run_id: str) -> str:
        return "unified-workbench:" + run_id

    @staticmethod
    def _summary(result: ToolResult) -> str:
        payload = {
            "status": result.status.value,
            "summary": result.summary[:3000],
            "error_code": result.error_code,
            "error_message": (result.error_message or "")[:2000],
            "evidence_ids": [item.evidence_id for item in result.evidence[:50]],
            "artifacts": [str(item) for item in result.artifacts[:50]],
        }
        return "统一工作台步骤回执：" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _title(value: str, fallback: str) -> str:
        text = str(value or "").strip()
        if text.startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                text = str(parsed.get("title") or parsed.get("summary") or fallback) if isinstance(parsed, dict) else fallback
            except ValueError:
                text = fallback
        return " ".join(text.split())[:120] or fallback

    @staticmethod
    def _structured_result(result: ToolResult) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for index, evidence in enumerate(result.evidence):
            items.append({"id": f"evidence-{index + 1}", "type": "observation",
                          "title": BlackboardCoordinator._title(evidence.summary, f"{evidence.source} · 工具观察"),
                          "summary": evidence.summary[:2000], "evidence_ids": [evidence.evidence_id]})
        for index, finding in enumerate(result.data.get("findings", [])):
            if not isinstance(finding, dict):
                continue
            if not finding.get("finding_id"):
                finding["finding_id"] = str(uuid5(NAMESPACE_URL, "canvas-finding:" + json.dumps(finding, sort_keys=True, ensure_ascii=False) + ":" + str(index)))
            refs = [ref for ref in finding.get("evidence_ids", [])
                    if ref in {e.evidence_id for e in result.evidence}]
            items.append({"id": f"finding-{index + 1}", "type": "finding",
                          "title": BlackboardCoordinator._title(finding.get("title"), "漏洞候选"),
                          "summary": str(finding.get("description") or "")[:2000],
                          "finding_id": finding.get("finding_id"), "evidence_ids": refs,
                          "verification_status": "pending" if refs else "insufficient"})
        for index, artifact in enumerate(result.artifacts):
            items.append({"id": f"artifact-{index + 1}", "type": "artifact", "title": "产出附件",
                          "summary": str(artifact), "evidence_ids": []})
        if not items:
            items.append({"id": "report-1", "type": "observation", "title": BlackboardCoordinator._title(result.summary, "Worker 报告"),
                          "summary": result.summary[:2000], "evidence_ids": []})
        return {"title": BlackboardCoordinator._title(result.summary, "执行结果包"), "items": items}

    @staticmethod
    def _sources(step: PlanStep, intents: list[dict[str, Any]], facts: list[dict[str, Any]]) -> tuple[list[str], str]:
        known = {fact.get("id") for fact in facts if isinstance(fact, dict)}
        explicit = step.inputs.get("fact_ids") or step.inputs.get("source_fact_ids") or []
        if isinstance(explicit, str):
            explicit = [explicit]
        cited = [fid for fid in explicit if isinstance(fid, str) and fid in known] if isinstance(explicit, list) else []
        dependencies = [item.get("to") for dep in step.dependencies for item in intents
                        if isinstance(item, dict) and (item.get("step_id") == dep or
                        str(item.get("description", "")).startswith(f"[{dep}] ")) and item.get("to") in known]
        sources = list(dict.fromkeys(cited + dependencies))
        if sources:
            return sources, "evidence" if cited else "process"
        return (["origin"] if "origin" in known else []), "unknown" if step.dependencies else "process"

    @staticmethod
    def _source_relations(step: PlanStep, sources: list[str], fallback: str) -> dict[str, str]:
        explicit = step.inputs.get("fact_ids") or step.inputs.get("source_fact_ids") or []
        if isinstance(explicit, str):
            explicit = [explicit]
        return {source: "evidence" if source in explicit else "unknown" if fallback == "unknown" else "process" for source in sources}

    @staticmethod
    def _hints(state: AgentState, step: PlanStep | None = None) -> list[dict[str, str]]:
        hints = [
            {"creator": "unified-workbench", "content": f"模块：{state.module_route}"},
            {"creator": "unified-workbench", "content": f"工作区：{state.workspace}"},
        ]
        if step is not None:
            hints.append({
                "creator": "unified-workbench",
                "content": f"步骤：{step.step_id}；工具：{step.tool_candidates[0] if step.tool_candidates else 'none'}",
            })
        if state.task.target_scope:
            hints.append({
                "creator": "unified-workbench",
                "content": "授权目标范围：" + ", ".join(state.task.target_scope),
            })
            hints.append({
                "creator": "unified-workbench",
                "content": "planner_scope_json:" + json.dumps(state.task.target_scope, ensure_ascii=False),
            })
        if state.task.constraints:
            hints.append({
                "creator": "unified-workbench",
                "content": "任务约束：\n" + "\n".join(state.task.constraints),
            })
        retest = state.retry_context.get("retest")
        if isinstance(retest, dict):
            hints.append({"creator": "unified-workbench", "content":
                "独立复核对象（历史数据，只作比较）：" + json.dumps(retest, ensure_ascii=False)[:4000]})
        if state.module_route == "penetration":
            policy = ("仅对授权 URL 的原路径允许 file 表单 POST（本地文件或只读 php://filter）；其他请求限 GET/HEAD"
                      if state.task.network_policy == SCOPED_POST_POLICY else
                      "授权 URL 允许 GET/HEAD/POST，请求体上限 4 KB；可携带会话 Cookie 与受限请求头，不跟随跳转"
                      if state.task.network_policy == SESSION_HTTP_POLICY else
                      "授权 URL 允许 GET/HEAD/POST，请求体上限 4 KB；不允许自定义请求头、Cookie 或跳转"
                      if state.task.network_policy == BOUNDED_HTTP_POLICY else
                      "授权 URL 的 GET/HEAD 只读探测"
                      if state.task.network_policy == "read_only_http" else "仅本地静态分析")
            hints.append({
                "creator": "unified-workbench",
                "content": "网络策略：" + policy,
            })
            prior = state.retry_context.get("prior_blackboard_fact")
            if isinstance(prior, dict) and state.task.network_policy == SCOPED_POST_POLICY:
                hints.append({"creator": "unified-workbench", "content":
                    "上次运行已结论事实（线索，需以本次工具回执重新核对）："
                    + json.dumps(prior, ensure_ascii=False)[:2400]})
        for artifact in state.input_artifacts[:200]:
            content = (
                f"材料 {artifact.relative_path} | {artifact.media_type} | "
                f"{artifact.size_bytes} bytes | sha256={artifact.sha256}"
            )
            if state.scenario == Scenario.PENETRATION_TEST:
                workspace = Path(state.workspace).resolve()
                candidate = (workspace / artifact.relative_path).resolve()
                if candidate.is_file() and workspace in candidate.parents:
                    try:
                        if artifact.media_type.startswith("text/") or candidate.suffix.casefold() in {
                            ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".html", ".url",
                        }:
                            excerpt = candidate.read_text(encoding="utf-8", errors="replace")[:4000].strip()
                            if excerpt:
                                content += f"\n内容摘录：{excerpt}"
                    except OSError:
                        pass
            hints.append({
                "creator": "unified-workbench",
                "content": content,
            })
        return hints

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=15, trust_env=False) as client:
                response = await client.request(method, path, **kwargs)
        except (httpx.HTTPError, OSError) as exc:
            raise BlackboardError(f"黑板服务不可用：{type(exc).__name__}") from exc
        if response.status_code >= 400:
            detail = response.text[:500]
            raise BlackboardError(f"黑板服务拒绝请求 HTTP_{response.status_code}: {detail}")
        try:
            return response.json()
        except ValueError as exc:
            raise BlackboardError("黑板服务返回了无效 JSON") from exc

    async def _remote_detail(self, project_id: str) -> dict[str, Any]:
        detail = await self._request("GET", "/projects/" + project_id)
        if not isinstance(detail, dict) or not isinstance(detail.get("project"), dict):
            raise BlackboardError("黑板项目回执格式无效")
        return detail

    async def sync_events_best_effort(self, state: AgentState) -> None:
        board = state.external_execution.get("blackboard", {})
        previous_error = board.get("sync_error")
        try:
            await self.sync_events(state)
            if previous_error:
                self.ledger.update_state(state.run_id, lambda current:
                    current.external_execution.get("blackboard", {}).pop("sync_error", None))
        except BlackboardError as exc:
            error_text = str(exc)
            board["sync_error"] = error_text
            if self.ledger.load_state(state.run_id) is not None:
                self.ledger.update_state(state.run_id, lambda current:
                    current.external_execution.setdefault("blackboard", {}).update(sync_error=error_text))
            if previous_error != error_text:
                self.ledger.append(state.run_id, "blackboard.sync.failed", {"error": error_text}, actor="blackboard_coordinator")

    async def sync_events(self, state: AgentState) -> None:
        lock = self._event_locks.setdefault(state.run_id, asyncio.Lock())
        async with lock:
            await self._sync_events(state)

    async def _sync_events(self, state: AgentState) -> None:
        board = state.external_execution.get("blackboard")
        if not isinstance(board, dict) or board.get("backend") != "remote":
            return
        project_id = board.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            return
        cursor = int(board.get("event_cursor") or 0)
        while True:
            page = await self._request("GET", f"/projects/{project_id}/events?after={cursor}&limit=200")
            if not isinstance(page, dict) or not isinstance(page.get("events"), list):
                raise BlackboardError("黑板事件游标回执无效")
            for item in page["events"]:
                if not isinstance(item, dict) or item.get("project_id") != project_id or not isinstance(item.get("sequence"), int):
                    raise BlackboardError("黑板事件项目身份无效")
                if item["sequence"] <= cursor or not isinstance(item.get("event_id"), str) or not isinstance(item.get("event_type"), str):
                    raise BlackboardError("黑板事件游标或身份无效")
                self.ledger.append(state.run_id, "runtime." + str(item.get("event_type")), {
                    "project_id": project_id, "intent_id": item.get("intent_id"),
                    "attempt_id": item.get("attempt_id"), "worker": item.get("worker"),
                    "runtime_sequence": item["sequence"], "timestamp": item.get("timestamp"),
                    **(item.get("payload") if isinstance(item.get("payload"), dict) else {}),
                }, actor="security_runtime", event_id=f"runtime:{project_id}:{item['event_id']}")
                cursor = item["sequence"]
            self.ledger.update_state(state.run_id, lambda current:
                current.external_execution.setdefault("blackboard", {}).update(event_cursor=cursor))
            if len(page["events"]) < 200:
                return

    async def penetration_dispatch_state(self, state: AgentState) -> tuple[str, bool]:
        """Resolve a lost activation receipt using the task's bound project."""
        board = state.external_execution.get("blackboard")
        project_id = board.get("project_id") if isinstance(board, dict) else None
        if (not isinstance(project_id, str) or not project_id
                or board.get("backend") != "remote"):
            raise BlackboardError("渗透任务缺少可核对的远程黑板绑定")
        project = (await self._remote_detail(project_id))["project"]
        if (project.get("id") != project_id
                or project.get("title") != project_title_for_run(state.run_id)
                or project.get("status") not in {"active", "completed", "stopped"}
                or not isinstance(project.get("dispatcher_enabled"), bool)):
            raise BlackboardError("渗透黑板项目身份或调度状态不匹配")
        return project["status"], project["dispatcher_enabled"]

    async def _find_existing(self, run_id: str) -> dict[str, Any] | None:
        payload = await self._request("GET", "/projects")
        if not isinstance(payload, list):
            raise BlackboardError("黑板项目列表格式无效")
        matches = [item for item in payload if isinstance(item, dict)
                   and item.get("title") == project_title_for_run(run_id)]
        if len(matches) > 1:
            raise BlackboardError("同一任务存在多个同名黑板项目，拒绝猜测绑定")
        return matches[0] if matches else None

    @staticmethod
    def _open_step_intent(detail: dict[str, Any], payload: dict[str, Any], step_id: str,
                          allowed_tools: list[str] | None = None) -> dict[str, Any] | None:
        intents = detail.get("intents")
        if not isinstance(intents, list):
            raise BlackboardError("黑板项目缺少可核对的意图列表")
        candidates = [item for item in intents if isinstance(item, dict)
                      and item.get("creator") == payload["creator"]
                      and str(item.get("description", "")).startswith(f"[{step_id}] ")
                      and not item.get("to") and not item.get("concluded_at")]
        if len(candidates) > 1:
            raise BlackboardError("同一步骤存在多个未完成黑板意图，拒绝重复执行")
        if not candidates:
            return None
        intent = candidates[0]
        if (intent.get("description") != payload["description"]
                or intent.get("from") != payload["from"]
                or (intent.get("tool_name") is not None
                    and intent.get("tool_name") not in (
                        allowed_tools if allowed_tools is not None else [payload.get("tool_name")]))
                or intent.get("worker") not in {None, payload["worker"]}):
            raise BlackboardError("已有黑板意图与当前步骤或来源事实不一致")
        intent_id = intent.get("id")
        if not isinstance(intent_id, str) or not intent_id:
            raise BlackboardError("黑板意图缺少有效 ID")
        return intent

    async def enter(self, state: AgentState) -> str:
        """Establish the task graph before planning any workbench task."""
        if state.status != RunStatus.RUNNING:
            raise BlackboardError("任务当前不允许进入黑板")
        board = state.external_execution.setdefault("blackboard", {})
        if board.get("status") in {"stopped", "completed", "stop_failed", "finalize_failed"}:
            raise BlackboardError("黑板项目已经进入终态")
        worker = self.worker_for(state.run_id)
        if self.local_mode and state.scenario != Scenario.PENETRATION_TEST:
            project_id = "local:" + state.run_id
            project = board.setdefault("graph", {
                "status": "active", "title": project_title_for_run(state.run_id),
                "facts": [{"id": "origin", "description": state.task.objective}],
                "intents": [], "next_fact": 1, "next_intent": 1,
            })
            if project.get("status") != "active" or project.get("title") != project_title_for_run(state.run_id):
                raise BlackboardError("本地黑板项目身份或状态不匹配")
            backend = "local"
        else:
            callback_enabled = not self.local_mode and bool(self.settings.security_runtime_callback_token) and state.module_route in {
                "penetration", "code_audit", "reverse",
            }
            if (state.scenario == Scenario.PENETRATION_TEST or callback_enabled) and not board.get("activation_token"):
                board["activation_token"] = secrets.token_urlsafe(32)
                self.ledger.save_state(state)
            project_id = board.get("project_id")
            if not isinstance(project_id, str) or not project_id:
                existing = await self._find_existing(state.run_id)
                project_id = existing.get("id") if existing else None
            if not isinstance(project_id, str) or not project_id:
                hints = self._hints(state)
                if callback_enabled:
                    hints.append({"creator": "unified-workbench",
                                  "content": f"workbench_planner:run_id={state.run_id};schema=1.1"})
                # Runtime-owned workbench projects are created disabled and
                # activated with the one-time credential after the run has
                # been classified.  Penetration projects keep the same
                # handoff because their adapter may activate them later.
                payload = {
                    "title": project_title_for_run(state.run_id),
                    "origin": f"统一工作台任务 {state.run_id}；模块：{state.module_route}",
                    "goal": state.task.objective,
                    "bootstrap_enabled": False,
                    "dispatcher_enabled": False,
                    **({'idempotency_key': f'workbench-run:{state.run_id}'} if callback_enabled else {}),
                    **({"dispatcher_activation_token": board["activation_token"]}
                       if state.scenario == Scenario.PENETRATION_TEST or callback_enabled else {}),
                    "hints": hints,
                }
                try:
                    created = await self._request("POST", "/projects", json=payload)
                    project = created.get("project") if isinstance(created, dict) else None
                    project_id = project.get("id") if isinstance(project, dict) else None
                except BlackboardError:
                    project_id = None
                if not isinstance(project_id, str) or not project_id:
                    recovered = await self._find_existing(state.run_id)
                    project_id = recovered.get("id") if recovered else None
                    if not isinstance(project_id, str) or not project_id:
                        raise BlackboardError("黑板创建项目未返回可核对的项目 ID")
            detail = await self._remote_detail(project_id)
            project = detail["project"]
            allowed_dispatcher_states = {False}
            marker_present = any(
                isinstance(hint, dict) and hint.get("creator") == "unified-workbench"
                and hint.get("content") == f"workbench_planner:run_id={state.run_id};schema=1.1"
                for hint in detail.get("hints", [])
            )
            if callback_enabled and marker_present and project.get("dispatcher_enabled") is True:
                # A retry can observe a project after the activation request
                # committed.  It is still the same authenticated workbench
                # project and must not be rejected as a duplicate.
                allowed_dispatcher_states.add(True)
            if (project.get("id") != project_id
                    or project.get("title") != project_title_for_run(state.run_id)
                    or project.get("status") != "active"
                    or project.get("dispatcher_enabled") not in allowed_dispatcher_states):
                raise BlackboardError("黑板项目身份或状态不匹配")
            backend = "remote"
            if callback_enabled and marker_present:
                board["planning_mode"] = "workbench"
        if board.get("status") is None:
            board.update({"backend": backend, "project_id": project_id,
                          "worker": worker, "status": "entered",
                          "title": project_title_for_run(state.run_id)})
            state.routing["blackboard_required"] = True
            self.ledger.save_state(state)
            self.ledger.append(state.run_id, "blackboard.entered", {
                "project_id": project_id, "backend": backend,
            }, actor="blackboard_coordinator")
        return project_id

    async def activate_runtime(self, state: AgentState) -> str:
        board = state.external_execution.get("blackboard", {})
        project_id = board.get("project_id")
        if board.get("planning_mode") != "workbench" or board.get("backend") != "remote":
            raise BlackboardError("任务没有绑定持续规划项目")
        title = project_title_for_run(state.run_id)
        try:
            project = await self._request("POST", f"/projects/{project_id}/dispatcher/activate", json={
                "title": title, "activation_token": board.get("activation_token"),
            })
        except BlackboardError:
            project = (await self._remote_detail(project_id))["project"]
        if (project.get("id") != project_id or project.get("title") != title
                or project.get("status") not in {"active", "completed", "stopped"}
                or project.get("dispatcher_enabled") is not True):
            raise BlackboardError("Runtime 尚未确认接管当前项目")
        def mark_active(current: AgentState) -> None:
            current.external_execution.setdefault("blackboard", {})["status"] = "active"
            current.external_execution.update(project_id=project_id, status="submitted")
        updated = self.ledger.update_state(state.run_id, mark_active)
        state.external_execution = updated.external_execution
        return project_id

    async def schedule(self, state: AgentState, step: PlanStep) -> str:
        """Put a selected step on the blackboard before its guardrail decision."""
        if not step.tool_candidates:
            raise BlackboardError("黑板步骤没有绑定工具")
        # The planner supplies capabilities; the blackboard records the
        # concrete tool assignment consumed by all later nodes.
        selected_tool = sorted(set(step.tool_candidates))[0]
        project_id = await self.enter(state)
        worker = self.worker_for(state.run_id)
        board = state.external_execution["blackboard"]
        if board.get("backend") == "local":
            project = board["graph"]
            sources, relation = self._sources(step, project["intents"], project["facts"])
            candidates = [item for item in project["intents"]
                          if item.get("step_id") == step.step_id and item.get("to") is None]
            if len(candidates) > 1:
                raise BlackboardError("同一步骤存在多个未完成黑板意图，拒绝重复调度")
            if candidates:
                intent = candidates[0]
                if (intent.get("from") != sources or intent.get("description") != step.objective
                        or intent.get("worker") is not None):
                    raise BlackboardError("已有黑板意图与当前步骤或来源事实不一致")
                assigned_tool = intent.get("tool_name")
                if assigned_tool is None and len(set(step.tool_candidates)) == 1:
                    assigned_tool = selected_tool
                    intent["tool_name"] = assigned_tool
                if assigned_tool not in step.tool_candidates:
                    raise BlackboardError("黑板意图没有为当前步骤分配有效工具")
                state.external_execution.setdefault("blackboard", {})["scheduled_tool"] = assigned_tool
                self.ledger.save_state(state)
                return str(intent["id"])
            intent_id = f"i{project['next_intent']:03d}"
            project["next_intent"] += 1
            project["intents"].append({
                "id": intent_id, "from": sources, "to": None,
                "creator": worker, "worker": None, "step_id": step.step_id,
                "description": step.objective, "tool_name": selected_tool, "concluded_at": None,
                "source_relation": relation, "source_relations": self._source_relations(step, sources, relation), "success_criteria": "; ".join(step.success_criteria),
            })
        else:
            detail = await self._remote_detail(project_id)
            facts = detail.get("facts") if isinstance(detail.get("facts"), list) else []
            sources, relation = self._sources(step, detail.get("intents", []), facts)
            description = f"[{step.step_id}] {step.objective}"
            if state.module_route == "penetration":
                policy = ("优先按上次已结论事实验证 file 表单 POST；请求体须为 file=<URL 编码值>，"
                          "只对授权 URL 原路径提交本地文件路径或 php://filter/convert.base64-encode/resource=index.php 形式的只读过滤器，"
                          "不得使用远程包含、执行类包装器、自定义头、Cookie 或跳转。"
                          if state.task.network_policy == SCOPED_POST_POLICY else
                          "允许对授权 URL 发起 GET/HEAD/POST，可在 URL 中携带参数并用请求体投递不超过 4 KB 的内容"
                          "（例如文件包含/RFI 题目的 php://input 载荷）；可携带会话 Cookie 与受限请求头"
                          "（Host/Authorization/Content-Type/Accept/Origin/Referer/X-Requested-With），不得跟随跳转；"
                          "拿到目标下发的会话 Cookie 后必须复用它继续做登录态接口测试。"
                          if state.task.network_policy == SESSION_HTTP_POLICY else
                          "允许对授权 URL 发起 GET/HEAD/POST，可在 URL 中携带参数并用请求体投递不超过 4 KB 的内容"
                          "（例如文件包含/RFI 题目的 php://input 载荷）；不得自定义请求头或 Cookie，不得跟随跳转。"
                          if state.task.network_policy == BOUNDED_HTTP_POLICY else
                          "仅对授权 URL 发起 GET/HEAD 请求，不发送请求体或跟随跳转。"
                          if state.task.network_policy == "read_only_http" else "仅做本地静态分析，不访问目标网络。")
                description = (f"[{step.step_id}] 黑板项目已创建并激活；直接使用当前黑板分配的工具分析目标，"
                               f"不要再次调用 penetration_module。任务目标：{state.task.objective[:2000]}。{policy}"
                               "只记录可核对的增量证据；无法在授权范围内完成时明确说明限制。")
            payload = {"from": sources, "description": description,
                       "tool_name": selected_tool, "creator": worker, "worker": None,
                       "source_relation": relation, "source_relations": self._source_relations(step, sources, relation), "success_criteria": "; ".join(step.success_criteria)}
            intent = self._open_step_intent(detail, payload, step.step_id, step.tool_candidates)
            if intent:
                assigned_tool = intent.get("tool_name")
                if assigned_tool is None and len(set(step.tool_candidates)) > 1:
                    raise BlackboardError("多候选黑板意图缺少工具分配")
                selected_tool = assigned_tool or selected_tool
            intent_id = intent["id"] if intent else None
            if intent_id is None:
                try:
                    created = await self._request("POST", f"/projects/{project_id}/intents", json=payload)
                    intent_id = created.get("id") if isinstance(created, dict) else None
                except BlackboardError:
                    intent_id = None
                if not isinstance(intent_id, str) or not intent_id:
                    recovered = await self._remote_detail(project_id)
                    intent = self._open_step_intent(recovered, payload, step.step_id, step.tool_candidates)
                    if intent and intent.get("tool_name") is None and len(set(step.tool_candidates)) > 1:
                        raise BlackboardError("多候选黑板意图缺少工具分配")
                    if intent:
                        selected_tool = intent.get("tool_name") or selected_tool
                    intent_id = intent["id"] if intent else None
                    if intent_id is None:
                        raise BlackboardError("黑板调度意图未返回可核对的意图 ID")
        state.external_execution.setdefault("blackboard", {})["scheduled_tool"] = selected_tool
        self.ledger.save_state(state)
        self.ledger.append(state.run_id, "blackboard.intent.scheduled", {
            "project_id": project_id, "intent_id": intent_id,
            "step_id": step.step_id, "tool": selected_tool,
        }, actor="blackboard_coordinator")
        return intent_id

    async def authorize_tool(self, state: AgentState, step: PlanStep) -> str:
        """Return the durable tool assignment for a scheduled step."""
        board = state.external_execution.get("blackboard")
        if not isinstance(board, dict):
            raise BlackboardError("任务尚未进入黑板")
        selected_tool = board.get("scheduled_tool")
        if selected_tool is None and state.module_route == "penetration" and len(step.tool_candidates) == 1:
            # Recovery of a pre-dispatcher activation receipt from older state.
            selected_tool = step.tool_candidates[0]
            board["scheduled_tool"] = selected_tool
        if not isinstance(selected_tool, str) or selected_tool not in step.tool_candidates:
            raise BlackboardError("黑板没有为当前步骤分配有效工具")
        if board.get("backend") == "local":
            intents = board.get("graph", {}).get("intents", [])
        else:
            project_id = board.get("project_id")
            if not isinstance(project_id, str) or not project_id:
                raise BlackboardError("黑板项目绑定无效")
            detail = await self._remote_detail(project_id)
            intents = detail.get("intents", [])
        matches = [item for item in intents if isinstance(item, dict)
                   and (item.get("step_id") == step.step_id
                        or str(item.get("description", "")).startswith(f"[{step.step_id}] "))
                   and not item.get("concluded_at")]
        if (len(matches) != 1 or matches[0].get("tool_name") != selected_tool
                and not (matches[0].get("tool_name") is None
                         and len(set(step.tool_candidates)) == 1)):
            raise BlackboardError("黑板意图与工具授权不一致")
        return selected_tool

    async def begin(self, state: AgentState, step: PlanStep) -> BlackboardBinding:
        if not step.tool_candidates:
            raise BlackboardError("黑板步骤没有绑定工具")
        board = state.external_execution.get("blackboard", {})
        selected_tool = board.get("scheduled_tool")
        if selected_tool is None:
            if len(set(step.tool_candidates)) > 1:
                raise BlackboardError("多候选步骤尚无黑板工具分配")
            selected_tool = step.tool_candidates[0]
        elif selected_tool not in step.tool_candidates:
            raise BlackboardError("黑板没有为当前步骤分配有效工具")
        if board.get("scheduled_tool") is not None and board.get("status") != "concluded":
            await self.authorize_tool(state, step)
        if not state.external_execution.get("blackboard", {}).get("project_id"):
            await self.enter(state)
        existing = BlackboardBinding.from_state(state.external_execution.get("blackboard"))
        if (existing and existing.step_id == step.step_id
                and state.external_execution.get("blackboard", {}).get("status") == "active"):
            try:
                await self.validate(state, existing)
            except BlackboardError as exc:
                if existing.backend != "remote":
                    raise
                detail = await self._remote_detail(existing.project_id)
                project = detail["project"]
                if (project.get("id") != existing.project_id
                        or project.get("title") != project_title_for_run(state.run_id)
                        or project.get("status") != "active"
                        or project.get("dispatcher_enabled") is not False):
                    raise BlackboardError("黑板项目身份或状态不匹配") from exc
                sources, _ = self._sources(step, detail.get("intents", []), detail.get("facts", []))
                payload = {"from": sources,
                           "description": f"[{step.step_id}] {step.objective}",
                           "tool_name": selected_tool,
                           "creator": existing.worker, "worker": existing.worker}
                intent = self._open_step_intent(detail, payload, step.step_id)
                if not intent or intent["id"] != existing.intent_id or intent.get("worker") is not None:
                    raise BlackboardError("已绑定的黑板意图不可重新领取") from exc
                claimed = await self._request("POST", f"/projects/{existing.project_id}/intents/{existing.intent_id}/heartbeat",
                                              json={"worker": existing.worker, "attempt_id": intent.get("attempt_id"), "claim": True})
                existing = BlackboardBinding(existing.backend, existing.project_id, existing.intent_id, existing.worker,
                                             existing.step_id, existing.fact_id, claimed.get("attempt_id"), existing.source_ids)
                state.external_execution["blackboard"].update(existing.as_dict())
                self.ledger.save_state(state)
                await self.sync_events_best_effort(state)
                await self.validate(state, existing)
            return existing
        if (existing and existing.step_id == step.step_id
                and state.external_execution.get("blackboard", {}).get("status") == "concluded"):
            latest = state.observations[-1] if state.observations else None
            retrying_failed_call = (
                latest is not None and latest.status != ToolStatus.SUCCESS
                and state.retry_counts.get(step.step_id, 0) > 0
            )
            resuming_remote_approval = (
                latest is not None and latest.error_code == "REMOTE_APPROVAL_REQUIRED"
                and bool(state.external_execution.get("remote_run_id"))
            )
            if not retrying_failed_call and not resuming_remote_approval:
                # A successful or unknown tool outcome cannot be replayed.
                # Explicit failed-call retries and remote approval polling
                # create a fresh intent linked to the prior receipt fact.
                raise BlackboardError("当前步骤已有黑板结论事实，拒绝重复执行工具")
        if (existing and existing.step_id == step.step_id
                and state.external_execution.get("blackboard", {}).get("status")
                in {"stop_failed", "finalize_failed"}):
            raise BlackboardError("黑板终态尚未核实，拒绝重复执行工具")
        worker = self.worker_for(state.run_id)
        if self.local_mode:
            project_id = state.external_execution["blackboard"]["project_id"]
            blackboard = state.external_execution.setdefault("blackboard", {})
            project = blackboard["graph"]
            if project.get("status") != "active":
                raise BlackboardError("本地黑板项目不处于 active 状态")
            sources, relation = self._sources(step, project["intents"], project["facts"])
            candidates = [item for item in project["intents"]
                          if item.get("step_id") == step.step_id and item.get("to") is None]
            if len(candidates) > 1:
                raise BlackboardError("同一步骤存在多个未完成黑板意图，拒绝重复执行")
            if candidates:
                intent = candidates[0]
                if (intent.get("from") != sources or intent.get("description") != step.objective
                        or intent.get("worker") not in {None, worker}):
                    raise BlackboardError("已有黑板意图与当前步骤或来源事实不一致")
                intent["worker"] = worker
                intent["attempt_id"] = str(uuid4())
                intent["execution_status"] = "running"
                intent_id = intent["id"]
            else:
                intent_id = f"i{project['next_intent']:03d}"
                project["next_intent"] += 1
                project["intents"].append({"id": intent_id, "from": sources, "to": None,
                                          "creator": worker, "worker": worker, "step_id": step.step_id,
                                          "description": step.objective, "tool_name": selected_tool, "concluded_at": None,
                                          "source_relation": relation, "source_relations": self._source_relations(step, sources, relation), "success_criteria": "; ".join(step.success_criteria),
                                          "attempt_id": str(uuid4()), "execution_status": "running"})
            intent = next(item for item in project["intents"] if item["id"] == intent_id)
            binding = BlackboardBinding("local", project_id, intent_id, worker, step.step_id,
                                        attempt_id=intent["attempt_id"], source_ids=tuple(sources))
        else:
            project_id = state.external_execution["blackboard"]["project_id"]
            detail = await self._remote_detail(project_id)
            project = detail["project"]
            if (project.get("title") != project_title_for_run(state.run_id)
                    or project.get("status") != "active"
                    or project.get("dispatcher_enabled") is not False):
                raise BlackboardError("黑板项目身份或状态不匹配")
            facts = detail.get("facts") if isinstance(detail.get("facts"), list) else []
            sources, relation = self._sources(step, detail.get("intents", []), facts)
            intent_payload = {
                "from": sources, "description": f"[{step.step_id}] {step.objective}",
                "tool_name": selected_tool, "creator": worker, "worker": worker,
                "source_relation": relation, "source_relations": self._source_relations(step, sources, relation), "success_criteria": "; ".join(step.success_criteria),
            }
            existing_intent = self._open_step_intent(detail, intent_payload, step.step_id)
            intent_id = existing_intent["id"] if existing_intent else None
            needs_claim = bool(existing_intent and existing_intent.get("worker") is None)
            if intent_id is None:
                try:
                    created_intent = await self._request(
                        "POST", f"/projects/{project_id}/intents", json=intent_payload,
                    )
                    intent_id = created_intent.get("id") if isinstance(created_intent, dict) else None
                    existing_intent = created_intent if isinstance(created_intent, dict) else None
                except BlackboardError:
                    # A lost response may follow a committed remote insert.
                    intent_id = None
                if not isinstance(intent_id, str) or not intent_id:
                    recovered = await self._remote_detail(project_id)
                    existing_intent = self._open_step_intent(recovered, intent_payload, step.step_id)
                    intent_id = existing_intent["id"] if existing_intent else None
                    needs_claim = bool(existing_intent and existing_intent.get("worker") is None)
                    if intent_id is None:
                        raise BlackboardError("黑板创建意图未返回可核对的意图 ID")
            if needs_claim:
                existing_intent = await self._request("POST", f"/projects/{project_id}/intents/{intent_id}/heartbeat",
                                                      json={"worker": worker, "attempt_id": existing_intent.get("attempt_id"), "claim": True})
            binding = BlackboardBinding("remote", project_id, intent_id, worker, step.step_id,
                                        sources[0] if sources else None,
                                        existing_intent.get("attempt_id") if isinstance(existing_intent, dict) else None,
                                        tuple(sources))
        previous_blackboard = state.external_execution.get("blackboard", {})
        state.external_execution["blackboard"] = {
            **previous_blackboard, **binding.as_dict(),
        }
        state.external_execution["blackboard"].update({
            "title": project_title_for_run(state.run_id),
            "status": "active", "tool": selected_tool,
            "scheduled_tool": selected_tool,
            "started_at": datetime.now(UTC).isoformat(),
        })
        state.routing["blackboard_required"] = True
        self.ledger.save_state(state)
        self.ledger.append(state.run_id, "blackboard.intent.started", {
            **binding.as_dict(),
            "project_id": binding.project_id, "intent_id": binding.intent_id,
            "worker": binding.worker, "step_id": binding.step_id,
            "backend": binding.backend, "tool": selected_tool,
        }, actor="blackboard_coordinator")
        await self.sync_events_best_effort(state)
        return binding

    async def validate(self, state: AgentState, binding: BlackboardBinding) -> None:
        if state.status != RunStatus.RUNNING:
            raise BlackboardError("任务当前不允许调用黑板工具")
        if binding.backend == "local":
            project = state.external_execution.get("blackboard", {}).get("graph")
            if not project or project.get("status") != "active":
                raise BlackboardError("本地黑板项目不处于 active 状态")
            intent = next((item for item in project["intents"] if item["id"] == binding.intent_id), None)
            if not intent or intent.get("worker") != binding.worker or intent.get("to") is not None or intent.get("attempt_id") != binding.attempt_id:
                raise BlackboardError("本地黑板意图已失效或已收束")
            return
        detail = await self._remote_detail(binding.project_id)
        project = detail["project"]
        intents = detail.get("intents") if isinstance(detail.get("intents"), list) else []
        intent = next(
            (item for item in intents if isinstance(item, dict) and item.get("id") == binding.intent_id), None
        )
        if (project.get("title") != project_title_for_run(state.run_id)
                or project.get("id") != binding.project_id
                or project.get("status") != "active"
                or project.get("dispatcher_enabled") is not False
                or not isinstance(intent, dict)
                or intent.get("worker") != binding.worker
                or intent.get("attempt_id") != binding.attempt_id
                or intent.get("to")
                or intent.get("concluded_at")):
            raise BlackboardError("黑板项目、意图或 Worker 分配已失效")

    async def heartbeat(self, state: AgentState, binding: BlackboardBinding) -> None:
        if binding.backend == "local":
            return
        await self._request(
            "POST", f"/projects/{binding.project_id}/intents/{binding.intent_id}/heartbeat",
            json={"worker": binding.worker, "attempt_id": binding.attempt_id},
        )
        await self.sync_events_best_effort(state)

    @asynccontextmanager
    async def lease(self, state: AgentState, binding: BlackboardBinding) -> AsyncIterator[None]:
        await self.validate(state, binding)
        stop = asyncio.Event()
        failure: list[BaseException] = []
        owner = asyncio.current_task()

        async def renew() -> None:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.heartbeat_interval_seconds)
                except TimeoutError:
                    try:
                        await self.heartbeat(state, binding)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        failure.append(exc)
                        if owner is not None:
                            owner.cancel()
                        return

        task = asyncio.create_task(renew())
        try:
            yield
        except asyncio.CancelledError:
            if failure:
                raise BlackboardError("黑板意图租约在工具执行期间失效") from failure[0]
            raise
        finally:
            stop.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if failure:
            raise BlackboardError("黑板意图租约在工具执行期间失效") from failure[0]

    async def conclude(self, state: AgentState, binding: BlackboardBinding, result: ToolResult) -> None:
        description = self._summary(result)
        outcome = "completed" if result.status == ToolStatus.SUCCESS else "timeout" if result.status == ToolStatus.TIMEOUT else "cancelled" if result.status == ToolStatus.DENIED else "failed"
        structured = self._structured_result(result)
        def matches_fact(fact: dict[str, Any]) -> bool:
            if fact.get("description") != description:
                return False
            # Older Runtime versions only persist description. New bundles must
            # also match the structured content when recovering a lost response.
            if "title" not in fact and "items" not in fact:
                return True
            if fact.get("title") != structured["title"] or len(fact.get("items") or []) != len(structured["items"]):
                return False
            return all(isinstance(actual, dict) and all(actual.get(key) == value for key, value in expected.items() if key != "id")
                       and actual.get("id") == f"{fact['id']}:{expected['id']}"
                       for actual, expected in zip(fact["items"], structured["items"]))
        board = state.external_execution.setdefault("blackboard", {})
        board["pending_conclusion"] = {
            "step_id": binding.step_id, "intent_id": binding.intent_id,
            "description": description,
            **structured,
        }
        self.ledger.save_state(state)
        if binding.backend == "local":
            project = state.external_execution.get("blackboard", {}).get("graph")
            if not project or project.get("status") != "active":
                raise BlackboardError("本地黑板项目已停止")
            intent = next((item for item in project["intents"] if item["id"] == binding.intent_id), None)
            if not intent or intent.get("to") is not None:
                raise BlackboardError("本地黑板意图已被其他执行者收束")
            fid = f"f{project['next_fact']:03d}"
            project["next_fact"] += 1
            structured = self._structured_result(result)
            for item in structured["items"]:
                item["id"] = f"{fid}:{item['id']}"
            project["facts"].append({"id": fid, "description": description, **structured})
            intent.update(to=fid, fact_id=fid, concluded_at=datetime.now(UTC).isoformat(), execution_status=outcome)
        else:
            try:
                payload = await self._request(
                    "POST", f"/projects/{binding.project_id}/intents/{binding.intent_id}/conclude",
                    json={"worker": binding.worker, "attempt_id": binding.attempt_id,
                          "description": description, "execution_status": outcome, **structured},
                )
            except BlackboardError:
                # The intent may have been concluded before its HTTP response
                # disappeared. Accept only the exact persisted result fact.
                detail = await self._remote_detail(binding.project_id)
                project = detail["project"]
                intents = detail.get("intents")
                facts = detail.get("facts")
                intent = next((item for item in intents if isinstance(item, dict)
                               and item.get("id") == binding.intent_id), None) if isinstance(intents, list) else None
                fid = intent.get("to") if isinstance(intent, dict) else None
                if (project.get("id") != binding.project_id
                        or project.get("title") != project_title_for_run(state.run_id)
                        or project.get("status") != "active"
                        or not isinstance(fid, str) or not fid or fid == "goal"
                        or intent.get("worker") != binding.worker
                        or intent.get("attempt_id") != binding.attempt_id
                        or intent.get("from") != list(binding.source_ids or (binding.fact_id or "origin",))
                        or not intent.get("concluded_at")
                        or not isinstance(facts, list)
                        or not any(isinstance(fact, dict) and fact.get("id") == fid
                                   and matches_fact(fact) for fact in facts)):
                    raise BlackboardError("黑板意图收束回执丢失且远端结果事实不匹配") from None
            else:
                fact = payload.get("fact") if isinstance(payload, dict) else None
                fid = fact.get("id") if isinstance(fact, dict) else None
                intent = payload.get("intent") if isinstance(payload, dict) else None
                if (not isinstance(fid, str) or not fid
                        or not matches_fact(fact)
                        or not isinstance(intent, dict)
                        or intent.get("id") != binding.intent_id
                        or intent.get("worker") != binding.worker
                        or intent.get("attempt_id") != binding.attempt_id
                        or intent.get("from") != list(binding.source_ids or (binding.fact_id or "origin",))
                        or intent.get("to") != fid
                        or not intent.get("concluded_at")):
                    raise BlackboardError("黑板意图收束回执未确认同一步骤的结果事实")
        updated = BlackboardBinding(binding.backend, binding.project_id, binding.intent_id,
                                    binding.worker, binding.step_id, fid, binding.attempt_id, binding.source_ids)
        state.external_execution["blackboard"] = {
            **state.external_execution.get("blackboard", {}), **updated.as_dict(),
            "status": "concluded", "fact_description": description,
        }
        state.external_execution["blackboard"].pop("pending_conclusion", None)
        self.ledger.save_state(state)
        self.ledger.append(state.run_id, "blackboard.intent.concluded", {
            "project_id": binding.project_id, "intent_id": binding.intent_id,
            "worker": binding.worker, "fact_id": fid, "tool_status": result.status.value,
            "attempt_id": binding.attempt_id,
            "call_id": state.external_execution["blackboard"].get("call_id"),
            "evidence_ids": [item.evidence_id for item in result.evidence],
        }, actor="blackboard_coordinator")
        await self.sync_events_best_effort(state)

    async def recover_conclusion(self, state: AgentState, step: PlanStep) -> bool:
        """Resume an observed tool result without invoking that tool again."""
        board = state.external_execution.get("blackboard")
        binding = BlackboardBinding.from_state(board)
        if (not binding or binding.step_id != step.step_id or not state.observations
                or state.observations[-1].error_code == "REMOTE_APPROVAL_REQUIRED"):
            return False
        result = state.observations[-1]
        description = self._summary(result)
        if board.get("status") == "concluded" and board.get("fact_description") == description:
            return True
        pending = board.get("pending_conclusion")
        if (board.get("status") != "active" or not isinstance(pending, dict)
                or pending.get("step_id") != step.step_id
                or pending.get("intent_id") != binding.intent_id
                or pending.get("description") != description):
            return False
        await self.conclude(state, binding, result)
        return True

    async def complete(self, state: AgentState) -> None:
        binding = BlackboardBinding.from_state(state.external_execution.get("blackboard"))
        if not binding:
            board = state.external_execution.get("blackboard", {})
            if (state.scenario == Scenario.PENETRATION_TEST or board.get("planning_mode") == "workbench") and board.get("backend") == "remote":
                project_id = board.get("project_id")
                detail = await self._remote_detail(project_id)
                project = detail["project"]
                intents = detail.get("intents")
                if (project.get("id") != project_id
                        or project.get("title") != project_title_for_run(state.run_id)
                        or project.get("status") != "completed"
                        or not isinstance(intents, list)
                        or not any(isinstance(item, dict) and item.get("to") == "goal"
                                   and item.get("concluded_at") for item in intents)):
                    raise BlackboardError("渗透黑板缺少已完成的真实目标意图")
                board["status"] = "completed"
                self.ledger.save_state(state)
                self.ledger.append(state.run_id, "blackboard.completed", {
                    "project_id": project_id, "source": "runtime_dispatcher",
                }, actor="blackboard_coordinator")
            return
        fact_id = binding.fact_id or "origin"
        description = (state.report.executive_summary if state.report else state.task.objective)[:5000]
        if binding.backend == "remote":
            try:
                completion = await self._request("POST", f"/projects/{binding.project_id}/complete", json={
                    "from": [fact_id], "description": description, "worker": binding.worker,
                })
            except BlackboardError:
                detail = await self._remote_detail(binding.project_id)
                project = detail["project"]
                intents = detail.get("intents")
                matches = [item for item in intents if isinstance(item, dict)
                           and item.get("to") == "goal" and item.get("worker") == binding.worker
                           and item.get("from") == [fact_id]
                           and item.get("description") == description
                           and item.get("concluded_at")] if isinstance(intents, list) else []
                if (project.get("id") != binding.project_id
                        or project.get("title") != project_title_for_run(state.run_id)
                        or project.get("status") != "completed" or len(matches) != 1):
                    raise BlackboardError("黑板完成回执丢失且远端目标意图不匹配") from None
            else:
                if (not isinstance(completion, dict)
                        or completion.get("to") != "goal"
                        or completion.get("worker") != binding.worker
                        or completion.get("from") != [fact_id]
                        or completion.get("description") != description
                        or not completion.get("concluded_at")):
                    raise BlackboardError("黑板完成回执未确认目标意图")
        else:
            project = state.external_execution.get("blackboard", {}).get("graph")
            if not isinstance(project, dict) or project.get("status") != "active":
                raise BlackboardError("本地黑板项目不能确认完成")
            project["facts"].append({"id": "goal", "description": description})
            project["intents"].append({
                "id": f"i{project['next_intent']:03d}", "from": [fact_id], "to": "goal",
                "worker": binding.worker, "creator": binding.worker,
                "description": description, "concluded_at": datetime.now(UTC).isoformat(),
            })
            project["next_intent"] += 1
            project["status"] = "completed"
        state.external_execution["blackboard"] = {
            **state.external_execution.get("blackboard", {}), "status": "completed",
        }
        self.ledger.save_state(state)
        self.ledger.append(state.run_id, "blackboard.completed", {
            "project_id": binding.project_id, "fact_id": fact_id, "worker": binding.worker,
        }, actor="blackboard_coordinator")
        await self.sync_events_best_effort(state)

    async def stop(self, state: AgentState, reason: str) -> None:
        board = state.external_execution.get("blackboard")
        if not isinstance(board, dict) or not board.get("project_id"):
            return
        binding = BlackboardBinding.from_state(board)
        project_id = binding.project_id if binding else board["project_id"]
        worker = binding.worker if binding else self.worker_for(state.run_id)
        current_status = board.get("status")
        if current_status in {"stopped", "completed", "stop_failed", "finalize_failed"}:
            return
        try:
            if (binding.backend if binding else board.get("backend")) == "remote":
                if state.scenario == Scenario.PENETRATION_TEST:
                    detail = await self._remote_detail(project_id)
                    if (detail["project"].get("id") != project_id
                            or detail["project"].get("title") != project_title_for_run(state.run_id)):
                        raise BlackboardError("渗透黑板项目身份不匹配")
                    if detail["project"].get("status") == "completed":
                        board["status"] = "completed"
                        self.ledger.save_state(state)
                        self.ledger.append(state.run_id, "blackboard.remote_completed", {
                            "project_id": project_id, "run_status": state.status.value,
                        }, actor="blackboard_coordinator")
                        return
                try:
                    stopped = await self._request(
                        "PUT", f"/projects/{project_id}/status", json={"status": "stopped"}
                    )
                except BlackboardError:
                    detail = await self._remote_detail(project_id)
                    stopped = detail["project"]
                if (not isinstance(stopped, dict)
                        or stopped.get("id") != project_id
                        or stopped.get("title") != project_title_for_run(state.run_id)
                        or stopped.get("status") != "stopped"):
                    raise BlackboardError("黑板停止回执未确认项目终态")
            else:
                project = state.external_execution.get("blackboard", {}).get("graph")
                if not isinstance(project, dict) or project.get("status") != "active":
                    raise BlackboardError("本地黑板项目不能确认停止")
                project["status"] = "stopped"
            state.external_execution["blackboard"] = {
                **state.external_execution.get("blackboard", {}), "status": "stopped", "stop_reason": reason,
            }
            self.ledger.save_state(state)
            self.ledger.append(state.run_id, "blackboard.stopped", {
                "project_id": project_id, "worker": worker, "reason": reason[:1000],
            }, actor="blackboard_coordinator")
            await self.sync_events_best_effort(state)
        except Exception as exc:
            state.external_execution["blackboard"] = {
                **state.external_execution.get("blackboard", {}),
                "status": "stop_failed",
                "stop_reason": reason,
                "stop_error": str(exc)[:1000] or type(exc).__name__,
            }
            self.ledger.save_state(state)
            self.ledger.append(state.run_id, "blackboard.stop_failed", {
                "project_id": project_id, "error_type": type(exc).__name__,
                "reason": reason[:1000],
            }, actor="blackboard_coordinator")
