"""Expose workbench tools only to an active, assigned blackboard intent."""
from __future__ import annotations

import asyncio
import hashlib
import json
import jsonschema
from pathlib import Path
from typing import Any
from uuid import uuid4
from urllib.parse import quote, urlparse

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from security_agent.bounded_http import MAX_CALLS_PER_INTENT as BOUNDED_CALLS_PER_INTENT
from security_agent.bounded_http import MAX_CALLS_PER_RUN as BOUNDED_CALLS_PER_RUN
from security_agent.bounded_http import POLICY as BOUNDED_HTTP_POLICY
from security_agent.bounded_http import validate_request
from security_agent.guardrail import Guardrail, GuardrailAction, autonomy_policy_skips_approval
from security_agent.mcp_agent import MCPAgentTool, PURE_TOOLS
from security_agent.mcp_approval import (destructive_tool, offline_safe, requires_approval,
                                         requires_context_approval)
from security_agent.mcp_boundaries import (AmbiguousMCPPathError, UNSCOPED_NETWORK_TOOLS,
                                           validate_workbench_arguments)
from security_agent.mcp_scope import requires_target_scope, target_values, validate_target_scope
from security_agent.penetration_integration import penetration_get, project_title_for_run
from security_agent.schemas import Finding, RunStatus, ToolContext, ToolResult, ToolStatus
from security_agent.scoped_file_post import POLICY as SCOPED_POST_POLICY
from security_agent.scoped_file_post import load_grant, state_has_grant, validate_post
from security_agent.session_http import MAX_CALLS_PER_INTENT as SESSION_CALLS_PER_INTENT
from security_agent.session_http import MAX_CALLS_PER_RUN as SESSION_CALLS_PER_RUN
from security_agent.session_http import POLICY as SESSION_HTTP_POLICY
from security_agent.session_http import UnsafeSessionHeaderError
from security_agent.session_http import validate_request as validate_session_request


class BlackboardInvocation(BaseModel):
    model_config = ConfigDict(extra='forbid')

    worker: str = Field(min_length=1, max_length=200)
    tool: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)
    request_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{8,200}$')
    arguments: dict[str, Any] = Field(default_factory=dict)


class BlackboardModelRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    worker: str = Field(min_length=1, max_length=200)
    request_id: str = Field(pattern=r'^[A-Za-z0-9_-]{8,200}$')
    attempt_id: str = Field(min_length=1, max_length=200)
    usage: dict[str, StrictInt] = Field(default_factory=dict)


def register_blackboard_mcp(app, runtime, settings):
    async def assignment(project_id, intent_id, worker, *, with_intent=False):
        try:
            detail = await penetration_get(
                settings.penetration_base_url, '/projects/' + quote(project_id, safe=''), 10,
            )
        except Exception as exc:
            raise HTTPException(409, '无法验证黑板任务分配') from exc
        if not isinstance(detail, dict) or not isinstance(detail.get('project'), dict):
            raise HTTPException(409, '黑板项目回执格式无效')
        project = detail['project']
        title = project.get('title')
        intents = detail.get('intents')
        if not isinstance(title, str) or not isinstance(intents, list):
            raise HTTPException(409, '黑板项目回执格式无效')
        run_id = title.removeprefix('sec-task-')
        state = runtime.ledger.load_state(run_id)
        intent = next((item for item in intents if isinstance(item, dict) and item.get('id') == intent_id), {})
        workspace = None
        if state and state.workspace:
            try:
                workspace = await asyncio.to_thread(Path(state.workspace).resolve, strict=True)
            except OSError:
                pass
        run_root = await asyncio.to_thread(settings.run_root.resolve)
        expected_workspace = run_root / run_id / 'workspace'
        binding = state.external_execution.get('blackboard') if state else None
        bound_project_id = (
            binding.get('project_id') if isinstance(binding, dict) else None
        ) or (state.external_execution.get('project_id') if state else None)
        bound_intent_id = binding.get('intent_id') if isinstance(binding, dict) else None
        # ``binding.worker`` is the unified-workbench coordinator identity
        # recorded while the task is being prepared.  Once the penetration
        # Dispatcher takes over, the active blackboard intent can be leased
        # to a Security Runtime worker (for example
        # ``claudecode_shared_model``).  The intent assignment below is the
        # authoritative worker check for that hand-off; comparing the two
        # identities directly would reject every legitimate Dispatcher call.
        bound_worker = binding.get('worker') if isinstance(binding, dict) else None
        if (
            not state or title != project_title_for_run(run_id)
            or state.status != RunStatus.RUNNING
            or (state.module_route == 'penetration' and not (
                isinstance(binding, dict) and binding.get('planning_mode') == 'workbench')
                and (len(state.plan) != 1 or state.plan[0].tool_candidates != ['penetration_module']))
            or bound_project_id != project_id
            or (bound_intent_id is not None and bound_intent_id != intent_id)
            or (bound_worker is not None and bound_worker != worker
                and intent.get('worker') != worker)
            or workspace != expected_workspace or not workspace.is_relative_to(run_root)
            or project.get('id') != project_id or project.get('status') != 'active'
            or not worker or intent.get('worker') != worker
            or intent.get('concluded_at') or intent.get('to')
        ):
            raise HTTPException(409, '仅允许正在执行的黑板意图调用工具')
        return (state, intent) if with_intent else state

    app.state.blackboard_assignment = assignment

    @app.post('/api/v1/mcp/blackboard/{project_id}/{intent_id}/model/reserve')
    async def reserve_model(project_id: str, intent_id: str, payload: BlackboardModelRequest):
        state, intent = await assignment(project_id, intent_id, payload.worker, with_intent=True)
        if payload.attempt_id != intent.get('attempt_id'):
            raise HTTPException(409, '模型请求的执行尝试已变更')
        binding = {'project_id': project_id, 'intent_id': intent_id,
                   'attempt_id': payload.attempt_id, 'worker': payload.worker}
        def reserve(current):
            requests = current.external_execution.setdefault('worker_model_requests', {})
            previous = requests.get(payload.request_id)
            if previous:
                if previous['blackboard'] != binding:
                    raise HTTPException(409, '模型请求 ID 已用于其他执行尝试')
                return
            if current.status != RunStatus.RUNNING:
                raise HTTPException(409, '任务不再允许模型调用')
            if max(current.budget.provider_requests_used, current.budget.model_calls_used) >= current.budget.max_model_calls:
                raise HTTPException(409, '任务模型调用预算已耗尽')
            current.budget.provider_requests_used += 1
            requests[payload.request_id] = {'blackboard': binding, 'status': 'reserved'}
        runtime.ledger.update_state(state.run_id, reserve)
        runtime.ledger.append(state.run_id, 'worker.model.started',
                              {'request_id': payload.request_id, 'blackboard': binding},
                              actor='security_runtime_worker', event_id=f'worker-model-start:{payload.request_id}')
        return {'request_id': payload.request_id, 'reserved': True}

    @app.post('/api/v1/mcp/blackboard/{project_id}/{intent_id}/model/complete')
    async def complete_model(project_id: str, intent_id: str, payload: BlackboardModelRequest):
        # A reservation was already checked while the lease was active. Retain
        # its usage receipt even if the project stopped during the response.
        detail = await penetration_get(settings.penetration_base_url,
                                       '/projects/' + quote(project_id, safe=''), 10)
        project = detail.get('project', {}) if isinstance(detail, dict) else {}
        title = project.get('title', '')
        state = runtime.ledger.load_state(title.removeprefix('sec-task-')) if title.startswith('sec-task-') else None
        if state is None:
            raise HTTPException(404, '模型请求对应的运行不存在')
        binding = {'project_id': project_id, 'intent_id': intent_id,
                   'attempt_id': payload.attempt_id, 'worker': payload.worker}
        keys = {'prompt_tokens', 'completion_tokens', 'cache_read_tokens'}
        if set(payload.usage) - keys or any(type(v) is not int or v < 0 for v in payload.usage.values()):
            raise HTTPException(422, '无效的模型用量回执')
        def finish(current):
            entry = current.external_execution.get('worker_model_requests', {}).get(payload.request_id)
            if not entry or entry['blackboard'] != binding:
                raise HTTPException(409, '模型请求未预留或关联不一致')
            if entry['status'] == 'completed':
                if entry['usage'] != payload.usage:
                    raise HTTPException(409, '模型回执 ID 已用于不同结果')
                return
            entry.update(status='completed', usage=payload.usage)
            current.budget.model_calls_used += 1
            current.budget.prompt_tokens_used += payload.usage.get('prompt_tokens', 0)
            current.budget.completion_tokens_used += payload.usage.get('completion_tokens', 0)
            current.budget.cache_read_tokens_used += payload.usage.get('cache_read_tokens', 0)
            current.budget.model_usage_recorded |= bool(payload.usage)
        runtime.ledger.update_state(state.run_id, finish)
        runtime.ledger.append(state.run_id, 'worker.model.completed',
                              {'request_id': payload.request_id, 'blackboard': binding, 'usage': payload.usage},
                              actor='security_runtime_worker', event_id=f'worker-model-finish:{payload.request_id}')
        return {'request_id': payload.request_id, 'completed': True}

    def available(state):
        return {
            'tool_' + hashlib.sha256((server['server_id'] + ':' + tool['name']).encode()).hexdigest()[:24]:
            MCPAgentTool(runtime, server, tool)
            for server, tool in runtime.agent_tools()
        }

    def module_tools(state):
        registry = getattr(app.state, 'workbench_tool_registry', None)
        if registry is None:
            return {}
        names = {
            'code_audit': 'workspace_security_audit',
            'reverse': 'reverse_module',
        }
        native_name = names.get(state.module_route)
        if not native_name:
            return {}
        try:
            native = registry.get(native_name)
        except Exception:
            return {}
        return {native_name: native}

    def module_version(name, tool):
        return f'workbench:{name}:{tool.manifest.version}'

    @app.get('/api/v1/mcp/blackboard/{project_id}/{intent_id}/tools')
    async def list_tools(project_id: str, intent_id: str, worker: str):
        state = await assignment(project_id, intent_id, worker)
        await runtime.refresh_agent_tools()
        tools = {**available(state), **module_tools(state)}
        return {'tools': [
            {'name': name, 'description': tool.manifest.description,
             'inputSchema': tool.manifest.input_schema,
             'version': module_version(name, tool) if name in module_tools(state) else tool.manifest.version}
            for name, tool in tools.items()
        ]}

    @app.post('/api/v1/mcp/blackboard/{project_id}/{intent_id}/invoke')
    async def invoke(project_id: str, intent_id: str, payload: BlackboardInvocation):
        worker = payload.worker
        state, assigned_intent = await assignment(project_id, intent_id, worker, with_intent=True)
        native_tools = module_tools(state)
        if payload.tool in native_tools:
            tool = native_tools[payload.tool]
            decision = Guardrail().evaluate(tool.manifest, payload.arguments, state.task.autonomy_policy)
            if decision.action == GuardrailAction.DENY:
                raise HTTPException(403, decision.reason)
            if assigned_intent.get('tool_name') not in {None, payload.tool}:
                raise HTTPException(409, '当前想法未分配该工具')
            if module_version(payload.tool, tool) != payload.version:
                raise HTTPException(409, '工作台适配器版本已变更，请重新发现工具')
            try:
                jsonschema.validate(payload.arguments, tool.manifest.input_schema)
            except jsonschema.ValidationError as exc:
                raise HTTPException(422, '工作台适配器参数不符合工具协议') from exc
            target = payload.arguments.get('target')
            if not isinstance(target, str):
                raise HTTPException(422, '工作台适配器目标无效')
            root = Path(state.workspace).resolve(strict=True)
            resolved = (root / target).resolve()
            if not resolved.is_relative_to(root) or not resolved.exists():
                raise HTTPException(422, '工作台适配器目标超出任务工作区')
            call_id = str(uuid4())
            binding = {'project_id': project_id, 'intent_id': intent_id,
                       'worker': worker, 'attempt_id': assigned_intent.get('attempt_id')}
            request_key = (f'{state.run_id}:{intent_id}:{assigned_intent.get("attempt_id") or ""}:'
                           f'{payload.request_id}') if payload.request_id else None
            receipt = {'call_id': call_id, 'status': 'running', 'run_id': state.run_id,
                       'tool': payload.tool, 'arguments': payload.arguments,
                       'blackboard': binding, 'idempotency_key': request_key}
            approval_id = None
            approval_key = f'native:{request_key}' if request_key else None
            existing = runtime.store.mcp_approval_for_request(approval_key) if approval_key else None
            if decision.action == GuardrailAction.REQUIRE_APPROVAL or existing:
                if not request_key:
                    raise HTTPException(422, '需审批的模块调用必须提供 request_id')
                approval_payload = {
                    'run_id': state.run_id, **binding, 'server_id': 'workbench-native',
                    'tool_name': payload.tool, 'tool': payload.tool, 'version': payload.version,
                    'arguments': payload.arguments,
                    'arguments_sha256': hashlib.sha256(json.dumps(payload.arguments, sort_keys=True,
                        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(),
                    'target': target, 'expected_impact': decision.reason,
                    'risk_level': f'R{int(decision.risk_level)}', 'approval_type': '逐次模块调用',
                    'policy_reasons': [decision.reason],
                }
                try:
                    record = runtime.store.request_mcp_approval(approval_key, approval_payload)
                except ValueError as exc:
                    raise HTTPException(409, str(exc)) from exc
                approval_id = record['approval_id']
                if record['status'] == 'pending':
                    return {'approval_required': True, 'approval_id': approval_id, 'status': 'pending'}
                if record['status'] == 'consumed':
                    try:
                        return await runtime.wait_for_request(request_key)
                    except TimeoutError as exc:
                        raise HTTPException(409, '模块调用仍在运行，请稍后使用相同 request_id 重试') from exc
                if record['status'] != 'approved':
                    raise HTTPException(409, '模块调用未获批准或审批已消费')
            if request_key:
                claimed, prior = runtime.store.claim_mcp_request(request_key, call_id, receipt)
                if not claimed:
                    if (not prior or prior.get('tool') != payload.tool
                            or prior.get('arguments') != payload.arguments
                            or prior.get('blackboard') != binding):
                        raise HTTPException(409, '工具请求 ID 已用于其他调用')
                    if prior.get('status') == 'running':
                        try:
                            return await runtime.wait_for_request(request_key)
                        except TimeoutError as exc:
                            raise HTTPException(409, '模块调用仍在运行，请稍后使用相同 request_id 重试') from exc
                    return prior
            try:
                fresh, fresh_intent = await assignment(project_id, intent_id, worker, with_intent=True)
                if fresh_intent.get('attempt_id') != assigned_intent.get('attempt_id'):
                    raise HTTPException(409, '黑板执行尝试已变更')
                if approval_id and runtime.store.transition_mcp_approval(approval_id, 'approved', 'consumed') is None:
                    raise HTTPException(409, '模块调用审批已失效或被重复使用')
                run_limit = fresh.budget.max_tool_calls
                if settings.blackboard_max_mcp_calls_per_run is not None:
                    run_limit = min(run_limit, settings.blackboard_max_mcp_calls_per_run)
                if not runtime.store.reserve_blackboard_call(
                    fresh.run_id, intent_id, run_limit=run_limit,
                    intent_limit=settings.blackboard_max_mcp_calls_per_intent,
                ):
                    raise HTTPException(409, '黑板工具调用预算已耗尽')
            except BaseException as exc:
                receipt.update(status='cancelled' if isinstance(exc, asyncio.CancelledError) else 'failed',
                               error=str(exc.detail) if isinstance(exc, HTTPException) else type(exc).__name__)
                runtime.store.finish_mcp_call(receipt)
                raise
            context = ToolContext(
                run_id=state.run_id, step_id=intent_id, workspace=state.workspace,
                allowed_paths=[state.workspace],
                module_base_url=(settings.reverse_base_url if state.module_route == 'reverse'
                                 else settings.penetration_base_url),
                external_execution={**state.external_execution, 'blackboard': binding},
                blackboard=binding, task_objective=state.task.objective,
                target_scope=list(state.task.target_scope), task_constraints=list(state.task.constraints),
                analysis_backend='local',
                input_artifacts=list(state.input_artifacts),
                mcp_generated_root=str(settings.mcp_generated_root),
                module_auth_token=settings.secmind_operator_token,
            )
            runtime.ledger.append(state.run_id, 'mcp.call.started', {
                'tool': payload.tool, 'call_id': call_id, 'blackboard': binding,
            }, actor='security_runtime_worker', event_id=f'module-start:{call_id}')
            try:
                async with asyncio.timeout(tool.manifest.timeout_seconds):
                    result = await tool.invoke(payload.arguments, context)
            except TimeoutError:
                result = ToolResult(status=ToolStatus.TIMEOUT, error_code='TOOL_TIMEOUT',
                                    error_message='单轮工具执行超时')
            except asyncio.CancelledError:
                receipt.update(status='interrupted', error='单轮工具执行取消，结果未确认')
                runtime.store.finish_mcp_call(receipt)
                runtime.ledger.append(state.run_id, 'mcp.call.interrupted', {
                    'tool': payload.tool, 'call_id': call_id, 'blackboard': binding,
                }, actor='security_runtime_worker', event_id=f'module-finish:{call_id}')
                raise
            except Exception as exc:
                result = ToolResult(status=ToolStatus.ERROR, error_code='TOOL_ERROR',
                                    error_message=f'单轮工具执行失败：{type(exc).__name__}')
            receipt_status = 'completed' if result.status.value == 'success' else 'failed'
            receipt.update({
                'status': receipt_status,
                'result': {'structuredContent': result.model_dump(mode='json')},
                'error': result.error_message,
            })
            runtime.store.finish_mcp_call(receipt)
            def merge_result(current):
                # The Planner callback may update this run while the native
                # adapter is executing. Merge into the newest snapshot so a
                # slow worker cannot erase decisions or parallel evidence.
                current.observations.append(result)
                known_evidence = {item.evidence_id for item in current.evidence}
                current.evidence.extend(item for item in result.evidence
                                        if item.evidence_id not in known_evidence)
                known_findings = {item.finding_id for item in current.findings}
                for raw in result.data.get('findings', []):
                    if current.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench':
                        # The result bundle owns candidate identity and verification.
                        # Keep adapter originals in the observation/receipt.
                        continue
                    try:
                        finding = Finding.model_validate(raw)
                    except Exception:
                        continue
                    if finding.finding_id not in known_findings:
                        current.findings.append(finding)
                current.external_execution.setdefault('blackboard', {})['last_call_id'] = call_id
            runtime.ledger.update_state(state.run_id, merge_result)
            runtime.ledger.append(state.run_id, 'mcp.call.' + receipt_status, {
                'tool': payload.tool, 'call_id': call_id, 'blackboard': binding,
                'status': result.status.value,
                'arguments': payload.arguments,
                'evidence_ids': [item.evidence_id for item in result.evidence],
                'result': receipt['result'],
            }, actor='security_runtime_worker', event_id=f'module-finish:{call_id}')
            return receipt
        tool = available(state).get(payload.tool)
        if not tool or tool.manifest.version != payload.version:
            raise HTTPException(409, '工具连接或协议已变更，请重新发现工具')
        if assigned_intent.get('tool_name') not in {None, tool.manifest.name}:
            raise HTTPException(409, '当前想法未分配该工具')
        arguments = payload.arguments
        policy_reasons = []
        if (tool.tool['name'] in UNSCOPED_NETWORK_TOOLS.get(tool.server['server_id'], set())
                and not target_values(arguments, tool.server['server_id'])):
            raise HTTPException(422, '无法识别网络目标，请在参数中明确填写目标后申请审批')
        try:
            validate_workbench_arguments(tool.server['server_id'], tool.tool['name'],
                                         arguments, Path(state.workspace))
        except AmbiguousMCPPathError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ValueError as exc:
            policy_reasons.append(str(exc))
        if state.task.network_policy == 'none' and not offline_safe(
            tool.server['server_id'], tool.tool['name']
        ):
            policy_reasons.append('任务未预先授权网络访问')
        if tool.server['server_id'] == 'kali-tools' and tool.tool['name'] in {
            'nmap_scan', 'naabu_scan', 'nikto_scan',
        }:
            target = arguments.get('target')
            ports = arguments.get('ports', '80,443')
            if not isinstance(target, str) or not isinstance(ports, str):
                raise HTTPException(422, 'Kali 扫描目标或端口无效')
            host_scopes = []
            for scope in state.task.target_scope:
                parsed = urlparse(scope if '://' in scope else '//' + scope)
                if parsed.hostname and parsed.path in {'', '/'} and not parsed.query and not parsed.fragment:
                    if parsed.port is None or ports == str(parsed.port):
                        host_scopes.append(scope)
            try:
                validate_target_scope('kali-tools', {'target': target}, host_scopes)
            except ValueError:
                policy_reasons.append('Kali 扫描目标或端口超出任务授权范围')
        if state.module_route == 'penetration' and tool.server['server_id'] == 'local-tscanplus':
            method = arguments.get('method', 'GET')
            empty = lambda value: value is None or value == ''
            if state.task.network_policy in {BOUNDED_HTTP_POLICY, SESSION_HTTP_POLICY}:
                # Bounded HTTP: the authorized URL plus a size-capped body.
                # Session HTTP additionally reuses a target-issued session
                # cookie, still on the same authorized URL and verbs.
                try:
                    (validate_session_request if state.task.network_policy == SESSION_HTTP_POLICY
                     else validate_request)(arguments)
                except UnsafeSessionHeaderError as exc:
                    raise HTTPException(422, str(exc)) from exc
                except ValueError as exc:
                    policy_reasons.append(str(exc))
            else:
                if (not isinstance(method, str) or method.upper() not in {'GET', 'HEAD', 'POST'}
                        or arguments.get('follow_redirect', False) is not False
                        or not empty(arguments.get('headers'))
                        or not empty(arguments.get('cookie'))):
                    policy_reasons.append('HTTP 方法、请求头、Cookie 或跳转参数超出任务预设策略')
                if method.upper() == 'POST':
                    grant = load_grant(settings)
                    if not state_has_grant(state, grant):
                        policy_reasons.append('当前运行没有预设 POST 授权')
                    else:
                        try:
                            validate_post(arguments, grant)
                        except ValueError as exc:
                            policy_reasons.append(str(exc))
                elif not empty(arguments.get('body')):
                    policy_reasons.append('GET/HEAD 请求携带请求体')
        if tool.tool['name'] not in PURE_TOOLS.get(tool.server['server_id'], set()):
            try:
                validate_target_scope(tool.server['server_id'], arguments, state.task.target_scope)
            except ValueError as exc:
                if (not target_values(arguments, tool.server['server_id'])
                        and requires_target_scope(tool.server['server_id'], arguments)):
                    raise HTTPException(422, str(exc)) from exc
                policy_reasons.append(str(exc))
        # The parent penetration_module approval does not authorize each
        # connected MCP tool or its arguments.
        workbench_mode = state.external_execution.get('blackboard', {}).get('planning_mode') == 'workbench'
        policy = (state.task.autonomy_policy if workbench_mode
                  or state.task.autonomy_policy == 'automatic_r3' else 'automatic')
        decision = Guardrail().evaluate(tool.manifest, arguments, policy)
        high_risk = (destructive_tool(tool.server['server_id'], tool.tool['name'], tool.server.get('risk_level'))
                     or decision.risk_level == 3)
        boundary_reasons = list(dict.fromkeys(policy_reasons))
        if decision.action == GuardrailAction.REQUIRE_APPROVAL:
            policy_reasons.append(decision.reason)
        policy_reasons = list(dict.fromkeys(policy_reasons))

        approval_id = None
        call_scope = ':'.join(filter(None, (intent_id, assigned_intent.get('attempt_id'))))
        request_key = ':'.join((state.run_id, project_id, call_scope, payload.request_id)) if payload.request_id else ''
        approval_by_risk = (requires_approval(tool.server['server_id'], tool.tool['name'], arguments)
                            and not ((workbench_mode or policy == 'automatic_r3')
                                     and autonomy_policy_skips_approval(decision.risk_level, policy)))
        context_approval = requires_context_approval(tool.server['server_id'], tool.tool['name'])
        if (policy_reasons or approval_by_risk or context_approval
                or request_key and runtime.store.mcp_approval_for_request(request_key)):
            if not payload.request_id:
                raise HTTPException(422, '需审批的 MCP 调用必须提供 request_id')
            try:
                approval_payload = {
                'run_id': state.run_id, 'project_id': project_id, 'intent_id': intent_id,
                'worker': worker, **({'attempt_id': assigned_intent['attempt_id']} if assigned_intent.get('attempt_id') else {}), 'server_id': tool.server['server_id'],
                'tool_name': tool.tool['name'], 'tool': payload.tool,
                'version': payload.version, 'arguments': arguments,
                'arguments_sha256': hashlib.sha256(json.dumps(
                    arguments, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                ).encode('utf-8')).hexdigest(),
                'target': ', '.join(target_values(arguments, tool.server['server_id'])) or next(
                    (str(arguments[key]) for key in ('target', 'url', 'host', 'path', 'file') if key in arguments), ''),
                'expected_impact': ('可能修改或删除目标数据、访问凭据或建立持久访问。' if high_risk
                                    else '可能向任务原授权范围之外发送网络请求或改变远端状态。'
                                    if policy_reasons else '可能读取或改变已连接服务及其目标的状态。'),
                'risk_level': 'R3' if high_risk or policy_reasons else 'R2',
                'approval_type': '高风险操作' if high_risk else '授权范围例外' if policy_reasons else '逐次工具调用',
                'policy_reasons': policy_reasons,
                }
                existing = runtime.store.mcp_approval_for_request(request_key)
                if existing is not None:
                    binding_fields = {'run_id', 'project_id', 'intent_id', 'worker', 'server_id',
                                      'tool_name', 'tool', 'version', 'arguments', 'arguments_sha256', 'attempt_id',
                                      'risk_level', 'policy_reasons'}
                    if existing.get('status') == 'pending':
                        binding_fields &= existing.keys()
                    approval_payload = {key: value for key, value in approval_payload.items()
                                        if key in binding_fields}
                record = runtime.store.request_mcp_approval(request_key, approval_payload)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
            approval_id = record['approval_id']
            if record['status'] == 'pending':
                return {'approval_required': True, 'approval_id': approval_id, 'status': 'pending'}
            if record['status'] == 'consumed':
                try:
                    return await runtime.wait_for_request(
                        f"{state.run_id}:{call_scope}:{payload.request_id}")
                except TimeoutError as exc:
                    raise HTTPException(409, 'MCP 调用仍在运行，请稍后使用相同 request_id 重试') from exc
            if record['status'] != 'approved':
                raise HTTPException(409, 'MCP 调用未获批准或已消费')

        async def validate_assignment():
            # Discovery, connection startup and the semaphore can all wait.
            # Recheck immediately before sending tools/call, not just when the
            # HTTP request originally arrived.
            current, current_intent = await assignment(project_id, intent_id, worker, with_intent=True)
            if current_intent.get('attempt_id') != assigned_intent.get('attempt_id'):
                raise HTTPException(409, '黑板执行尝试已变更，请重新发现工具')
            if approval_id and runtime.store.transition_mcp_approval(approval_id, 'approved', 'consumed') is None:
                raise HTTPException(409, 'MCP 审批已失效或被重复使用')
            run_limit = settings.blackboard_max_mcp_calls_per_run
            intent_limit = settings.blackboard_max_mcp_calls_per_intent
            if (current.task.network_policy == SCOPED_POST_POLICY
                    and state_has_grant(current, load_grant(settings))):
                # This one-off POST authorization has its own 40/60 ceiling.
                # Removing the general bridge limit must not widen that grant.
                run_limit = min(run_limit, 60) if run_limit is not None else 60
                intent_limit = min(intent_limit, 40) if intent_limit is not None else 40
            elif current.task.network_policy in {BOUNDED_HTTP_POLICY, SESSION_HTTP_POLICY}:
                # Body-carrying requests under an explicit operator grant keep
                # a finite ceiling even when the global counter is unlimited.
                session = current.task.network_policy == SESSION_HTTP_POLICY
                calls_per_run = SESSION_CALLS_PER_RUN if session else BOUNDED_CALLS_PER_RUN
                calls_per_intent = SESSION_CALLS_PER_INTENT if session else BOUNDED_CALLS_PER_INTENT
                if calls_per_run is not None:
                    run_limit = (min(run_limit, calls_per_run)
                                 if run_limit is not None else calls_per_run)
                if calls_per_intent is not None:
                    intent_limit = (min(intent_limit, calls_per_intent)
                                    if intent_limit is not None else calls_per_intent)
            if not runtime.store.reserve_blackboard_call(
                current.run_id, intent_id,
                run_limit=min(run_limit, current.budget.max_tool_calls) if run_limit is not None
                else current.budget.max_tool_calls,
                intent_limit=intent_limit,
            ):
                raise HTTPException(409, '黑板工具调用预算已耗尽')

        try:
            return await runtime.invoke(
                tool.server['server_id'], tool.tool['name'], arguments, approved=True, run_id=state.run_id,
                expected_connection=runtime.connection_fingerprint(tool.server),
                expected_tool=runtime.tool_fingerprint(tool.tool),
                blackboard={'project_id': project_id, 'intent_id': intent_id, 'worker': worker,
                            **({'attempt_id': assigned_intent['attempt_id']} if assigned_intent.get('attempt_id') else {})},
                before_call=validate_assignment,
                request_id=payload.request_id,
                scope_override_approval_id=approval_id if boundary_reasons else None,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except OSError as exc:
            raise HTTPException(409, '黑板任务工作区不可用') from exc
