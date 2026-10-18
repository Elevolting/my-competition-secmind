import asyncio
import hashlib
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult

from security_agent.api import build_runtime
from security_agent.blackboard_mcp import register_blackboard_mcp
from security_agent.blackboard_mcp_server import create_server
from security_agent.bounded_http import POLICY as BOUNDED_HTTP_POLICY
from security_agent.operations import OperationsStore
from security_agent.operations_api import register_operations
from security_agent.schemas import AgentState, PlanStep, RunStatus, Scenario, TaskRequest
from security_agent.scoped_file_post import POLICY as SCOPED_POST_POLICY
from security_agent.scoped_file_post import REQUEST_ID as SCOPED_POST_REQUEST_ID
from security_agent.scoped_file_post import SOURCE_RUN_ID as SCOPED_POST_SOURCE_RUN_ID
from security_agent.scoped_file_post import Grant, grant_path


async def setup_bridge(settings, monkeypatch, run_id='bridge-test'):
    monkeypatch.setattr('security_agent.bundled_integrity.tscanplus_trusted', lambda _server: True)
    service, _, gateway, _ = build_runtime(settings)
    runtime = service.orchestrator.mcp_runtime
    workspace = settings.run_root / run_id / 'workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    state = AgentState(run_id=run_id, task=TaskRequest(objective='Decode Base64 in assigned test'),
        scenario=Scenario.PENETRATION_TEST, module_route='penetration', status=RunStatus.RUNNING,
        workspace=str(workspace),
        external_execution={'module': 'penetration', 'status': 'submitted', 'project_id': 'proj-test'},
        plan=[PlanStep(step_id='submit', objective='submit', agent_role='executor',
                       tool_candidates=['penetration_module'])])
    service.ledger.save_state(state)
    detail = {'project': {'id': 'proj-test', 'title': 'sec-task-' + run_id, 'status': 'active'},
              'intents': [{'id': 'i001', 'worker': 'worker-test', 'to': None, 'concluded_at': None}]}

    async def get_detail(*args):
        return detail

    monkeypatch.setattr('security_agent.blackboard_mcp.penetration_get', get_detail)
    app = FastAPI()
    register_blackboard_mcp(app, runtime, settings)
    register_operations(app, None, runtime, None)
    transport = httpx.ASGITransport(app=app)
    bridge = create_server('http://workbench.test', 'proj-test', 'i001', 'worker-test',
                           settings.run_root, transport=transport)
    return service, gateway, detail, transport, bridge


async def test_trace_search_bridge_is_bound_to_active_assignment(settings, monkeypatch):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    try:
        event = service.ledger.append('bridge-test', 'mcp.call.completed', {
            'blackboard': {'intent_id': 'other-intent', 'worker': 'other-worker'},
            'result': {'content': [{'type': 'text', 'text': 'trace marker'}]}})
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            names = {tool['name'] for tool in (await client.get(prefix + '/tools?worker=worker-test')).json()['tools']}
            assert {'search_all_worker_traces', 'get_worker_trace'} <= names
            request = {'worker': 'worker-test', 'tool': 'search_all_worker_traces', 'version': '1.0',
                       'arguments': {'keyword': 'trace marker'}}
            response = await client.post(prefix + '/invoke', json=request)
            assert response.status_code == 200
            receipt = response.json()
            assert receipt['call_id'] and receipt['status'] == 'completed'
            assert receipt['result']['structuredContent']['data']['items'][0]['trace_id'] == event.event_id
            request['arguments']['run_id'] = 'other-run'
            assert (await client.post(prefix + '/invoke', json=request)).status_code == 422
            request['arguments'].pop('run_id')
            request['worker'] = 'unassigned-worker'
            assert (await client.post(prefix + '/invoke', json=request)).status_code == 409
    finally:
        await gateway.close()


async def test_mcp_approval_expires_when_intent_attempt_changes(settings, monkeypatch):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    detail['intents'][0]['attempt_id'] = 'attempt-one'
    record = runtime.store.request_mcp_approval('attempt-change-test', {
        'run_id': 'bridge-test', 'project_id': 'proj-test', 'intent_id': 'i001',
        'worker': 'worker-test', 'attempt_id': 'attempt-one',
        'server_id': 'test', 'tool_name': 'test', 'version': 'test',
    })
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            path = '/api/v1/mcp/approvals/' + record['approval_id']
            assert (await client.get(path)).json()['status'] == 'pending'
            assert await transport.app.state.mcp_approval_is_live(record)
            detail['intents'][0]['attempt_id'] = 'attempt-two'
            assert (await client.get(path)).json()['status'] == 'expired'
            assert not await transport.app.state.mcp_approval_is_live(record)
            assert (await client.post(path, json={'decision': 'approve'})).status_code == 409
    finally:
        await gateway.close()


async def test_legacy_approval_expires_when_intent_gains_attempt_id(settings, monkeypatch):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    record = runtime.store.request_mcp_approval('legacy-attempt-test', {
        'run_id': 'bridge-test', 'project_id': 'proj-test', 'intent_id': 'i001',
        'worker': 'worker-test', 'server_id': 'test', 'tool_name': 'test', 'version': 'test',
    })
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            path = '/api/v1/mcp/approvals/' + record['approval_id']
            assert (await client.get(path)).json()['status'] == 'pending'
            detail['intents'][0]['attempt_id'] = 'new-attempt'
            assert (await client.get(path)).json()['status'] == 'expired'
            assert (await client.post(path, json={'decision': 'approve'})).status_code == 409
    finally:
        await gateway.close()


async def test_workbench_model_reservation_is_shared_atomic_and_replay_safe(settings, monkeypatch):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    state.budget.max_model_calls = 4
    service.ledger.save_state(state)
    detail['intents'][0]['attempt_id'] = 'attempt-one'
    prefix = '/api/v1/mcp/blackboard/proj-test/i001/model'
    payload = {'worker': 'worker-test', 'attempt_id': 'attempt-one', 'request_id': 'model-request-001'}
    try:
        await service.orchestrator._model_event(state, 'llm.stream.started', {'trace_id': 'planner-one'})
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            responses = await asyncio.gather(*[client.post(prefix + '/reserve', json={
                **payload, 'request_id': f'model-request-{i:03}'}) for i in range(8)])
            assert sum(r.status_code == 200 for r in responses) == 3
            assert (await client.post(prefix + '/reserve', json={**payload, 'attempt_id': 'old'})).status_code == 409
            reserved = next(r.json()['request_id'] for r in responses if r.status_code == 200)
            payload['request_id'] = reserved
            assert (await client.post(prefix + '/reserve', json=payload)).status_code == 200
            assert service.ledger.load_state(state.run_id).budget.provider_requests_used == 4
            usage = {'prompt_tokens': 7, 'completion_tokens': 2}
            assert (await client.post(prefix + '/complete', json={**payload, 'usage': {'prompt_tokens': -1}})).status_code == 422
            assert (await client.post(prefix + '/complete', json={**payload, 'usage': {'prompt_tokens': True}})).status_code == 422
            await asyncio.gather(*[client.post(prefix + '/complete', json={**payload, 'usage': usage}) for _ in range(5)])
            await service.orchestrator._model_event(state, 'llm.stream.completed', {
                'trace_id': 'planner-one', 'usage': {'prompt_tokens': 3, 'completion_tokens': 1}})
            service.ledger.save_state(state)  # A stale graph snapshot must preserve Worker usage.
            current = service.ledger.load_state(state.run_id)
            assert current.budget.model_calls_used == 2 and current.budget.prompt_tokens_used == 10
            assert current.external_execution['worker_model_requests'][reserved]['status'] == 'completed'
            assert (await client.post(prefix + '/complete', json={**payload, 'usage': {'prompt_tokens': 8}})).status_code == 409
            current.status = RunStatus.PARTIAL
            service.ledger.save_state(current)
            other = next(r.json()['request_id'] for r in responses if r.status_code == 200 and r.json()['request_id'] != reserved)
            assert (await client.post(prefix + '/complete', json={**payload, 'request_id': other, 'usage': usage})).status_code == 200
            assert service.ledger.load_state(state.run_id).budget.model_calls_used == 3
    finally:
        await gateway.close()


@pytest.mark.parametrize('route,tool_name', [('code_audit', 'workspace_security_audit'), ('reverse', 'reverse_module')])
@pytest.mark.parametrize('autonomy', ['graded', 'approval_all'])
async def test_native_round_adapters_preserve_assignment_approval_evidence_and_idempotency(
        settings, monkeypatch, route, tool_name, autonomy):
    from security_agent.schemas import Evidence, RiskLevel, ToolManifest, ToolResult, ToolStatus
    from security_agent.tools import BaseTool, ToolRegistry
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.module_route = route
    state.task.autonomy_policy = autonomy
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    detail['intents'][0].update(attempt_id='attempt-one', tool_name=tool_name)
    calls = []

    class RoundTool(BaseTool):
        manifest = ToolManifest(name=tool_name, version='test', description='Single exploration round',
            scenarios=[Scenario.CODE_AUDIT], input_schema={'type': 'object', 'properties': {'target': {'type': 'string'}},
                'required': ['target']}, output_schema={}, risk_level=RiskLevel.R1)

        async def invoke(self, args, context):
            calls.append(context)
            assert context.analysis_backend == 'local' and context.blackboard['attempt_id'] == 'attempt-one'
            return ToolResult(status=ToolStatus.SUCCESS, data={'findings': []}, evidence=[
                Evidence(evidence_id='native-evidence', source='mock-adapter', summary='真实适配器回执')])

    registry = ToolRegistry()
    registry.register(RoundTool())
    transport.app.state.workbench_tool_registry = registry
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            spec = next(t for t in (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'] if t['name'] == tool_name)
            payload = {'worker': 'worker-test', 'tool': tool_name, 'version': spec['version'],
                       'arguments': {'target': '.'}, 'request_id': 'native-request-001'}
            response = await client.post(prefix + '/invoke', json=payload)
            assert response.status_code == 200
            if autonomy == 'approval_all':
                assert response.json()['approval_required'] and not calls
                approval = response.json()['approval_id']
                drift = await client.post(prefix + '/invoke', json={**payload, 'arguments': {'target': '..'}})
                assert drift.status_code in {409, 422} and not calls
                assert (await client.post('/api/v1/mcp/approvals/' + approval, json={'decision': 'approve'})).status_code == 200
                response = await client.post(prefix + '/invoke', json=payload)
            assert response.json()['status'] == 'completed' and len(calls) == 1
            replay = await client.post(prefix + '/invoke', json=payload)
            assert replay.status_code == 200 and replay.json()['call_id'] == response.json()['call_id'] and len(calls) == 1
            current = service.ledger.load_state(state.run_id)
            assert current.evidence[0].evidence_id == 'native-evidence' and not current.findings
            assert service.orchestrator.mcp_runtime.store.blackboard_calls_used(state.run_id) == 1
            events = service.ledger.events(state.run_id)
            started = next(e for e in events if e.event_type == 'mcp.call.started')
            completed = next(e for e in events if e.event_type == 'mcp.call.completed')
            assert started.payload['blackboard'] == completed.payload['blackboard']
            assert completed.payload['arguments'] == payload['arguments']
    finally:
        await gateway.close()


async def test_native_concurrent_replay_waits_for_terminal_receipt(settings, monkeypatch):
    from security_agent.schemas import RiskLevel, ToolManifest, ToolResult, ToolStatus
    from security_agent.tools import BaseTool, ToolRegistry

    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.module_route = 'code_audit'
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    detail['intents'][0].update(attempt_id='attempt-one', tool_name='workspace_security_audit')
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    class WaitingTool(BaseTool):
        manifest = ToolManifest(name='workspace_security_audit', version='test',
            description='Local audit', scenarios=[Scenario.CODE_AUDIT],
            input_schema={'type': 'object', 'properties': {'target': {'type': 'string'}},
                          'required': ['target']}, output_schema={}, risk_level=RiskLevel.R1)

        async def invoke(self, args, context):
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            return ToolResult(status=ToolStatus.SUCCESS, data={'findings': []})

    registry = ToolRegistry()
    registry.register(WaitingTool())
    transport.app.state.workbench_tool_registry = registry
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = next(item for item in listed.json()['tools'] if item['name'] == 'workspace_security_audit')
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'arguments': {'target': '.'}, 'request_id': 'native-concurrent-001'}
            first = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await entered.wait()
            replay = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await asyncio.sleep(0.1)
            assert not replay.done()
            release.set()
            responses = await asyncio.gather(first, replay)
            assert all(response.status_code == 200 for response in responses)
            assert responses[0].json() == responses[1].json()
            assert responses[0].json()['status'] == 'completed'
            assert calls == 1
    finally:
        release.set()
        await gateway.close()


async def test_native_consumed_approval_waits_for_terminal_receipt(settings, monkeypatch):
    from security_agent.schemas import RiskLevel, ToolManifest
    from security_agent.tools import BaseTool, ToolRegistry

    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.module_route = 'code_audit'
    state.task.autonomy_policy = 'approval_all'
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    detail['intents'][0].update(attempt_id='attempt-one', tool_name='workspace_security_audit')

    class AuditTool(BaseTool):
        manifest = ToolManifest(name='workspace_security_audit', version='test',
            description='Local audit', scenarios=[Scenario.CODE_AUDIT],
            input_schema={'type': 'object', 'properties': {'target': {'type': 'string'}},
                          'required': ['target']}, output_schema={}, risk_level=RiskLevel.R1)

        async def invoke(self, args, context):
            raise AssertionError('replayed call must not execute')

    registry = ToolRegistry()
    registry.register(AuditTool())
    transport.app.state.workbench_tool_registry = registry
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = next(item for item in listed.json()['tools'] if item['name'] == 'workspace_security_audit')
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'arguments': {'target': '.'}, 'request_id': 'native-consumed-001'}
            pending = await client.post(prefix + '/invoke', json=payload)
            assert pending.json()['approval_required']
            runtime = service.orchestrator.mcp_runtime
            assert runtime.store.transition_mcp_approval(
                pending.json()['approval_id'], 'pending', 'consumed')
            request_key = 'bridge-test:i001:attempt-one:native-consumed-001'
            receipt = {'call_id': 'native-fixed-call', 'status': 'running', 'run_id': 'bridge-test',
                       'tool': 'workspace_security_audit', 'arguments': payload['arguments'],
                       'blackboard': {'project_id': 'proj-test', 'intent_id': 'i001',
                                      'worker': 'worker-test', 'attempt_id': 'attempt-one'},
                       'idempotency_key': request_key}
            claimed, _ = runtime.store.claim_mcp_request(request_key, receipt['call_id'], receipt)
            assert claimed
            replay = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await asyncio.sleep(0.1)
            assert not replay.done()
            receipt.update(status='completed', completed_at='2026-10-14T00:00:00+00:00')
            runtime.store.finish_mcp_call(receipt)
            response = await replay
            assert response.status_code == 200
            assert response.json() == receipt
    finally:
        await gateway.close()


async def test_side_effect_approval_binds_arguments_and_prevents_replay(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-burp', 'name': 'Burp', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'write_comment', 'description': 'Write project comment',
            'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'fixture-call'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'read_only_http'
    service.ledger.save_state(state)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'approval-test-001', 'arguments': {'comment': 'approved'}}
            pending = await client.post(prefix + '/invoke', json=payload)
            assert pending.json()['approval_required'] and not calls
            approval_id = pending.json()['approval_id']
            record = runtime.store.mcp_approval(approval_id)
            assert record['arguments'] == payload['arguments'] and len(record['arguments_sha256']) == 64
            changed = await client.post(prefix + '/invoke', json={**payload, 'arguments': {'comment': 'changed'}})
            assert changed.status_code == 409 and not calls
            approved = await client.post('/api/v1/mcp/approvals/' + approval_id,
                                         json={'decision': 'approve'})
            assert approved.status_code == 200
            result = await client.post(prefix + '/invoke', json=payload)
            assert result.status_code == 200 and len(calls) == 1
            replay = await client.post(prefix + '/invoke', json=payload)
            assert replay.status_code == 409 and len(calls) == 1
            denied_payload = {**payload, 'request_id': 'approval-test-002'}
            denied_request = await client.post(prefix + '/invoke', json=denied_payload)
            denied_id = denied_request.json()['approval_id']
            assert (await client.post('/api/v1/mcp/approvals/' + denied_id,
                                      json={'decision': 'deny'})).status_code == 200
            assert (await client.post(prefix + '/invoke', json=denied_payload)).status_code == 409
            state.status = RunStatus.PARTIAL
            service.ledger.save_state(state)
            assert (await client.post('/api/v1/mcp/approvals/' + denied_id,
                                      json={'decision': 'approve'})).status_code == 409
            assert len(calls) == 1
    finally:
        await gateway.close()


async def test_approval_cannot_survive_policy_change(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'read_only_http'
    service.ledger.save_state(state)
    server = {'server_id': 'local-burp', 'name': 'Burp', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'write_comment', 'description': 'Write project comment',
            'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        calls.append(args)
        return {'status': 'completed', 'call_id': 'unexpected'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            spec = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'policy-drift-001', 'arguments': {'comment': 'fixture'}}
            pending = await client.post(prefix + '/invoke', json=payload)
            assert pending.status_code == 200 and pending.json()['approval_required']
            approval_id = pending.json()['approval_id']
            assert runtime.store.transition_mcp_approval(approval_id, 'pending', 'approved')
            state.task.network_policy = 'none'
            service.ledger.save_state(state)
            stale = await client.post(prefix + '/invoke', json=payload)
            assert stale.status_code == 409 and not calls
    finally:
        await gateway.close()


async def test_outside_file_approval_exposes_only_that_file(settings, monkeypatch):
    from security_agent.local_mcp import artifact_path

    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    external = settings.run_root / 'external-fixture'
    external.mkdir(parents=True)
    allowed = external / 'allowed.txt'
    sibling = external / 'sibling.txt'
    allowed.write_text('approved fixture', encoding='utf-8')
    sibling.write_text('not approved', encoding='utf-8')
    captured_roots = []
    original_session = runtime.session

    @asynccontextmanager
    async def capturing_session(server, *, allowed_roots=None):
        captured_roots.extend(allowed_roots or [])
        async with original_session(server, allowed_roots=allowed_roots) as client:
            yield client

    monkeypatch.setattr(runtime, 'session', capturing_session)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            specs = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools']
            spec = next(item for item in specs if 'hash_file' in item['description'])
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'outside-file-001', 'arguments': {'path': str(allowed)}}
            pending = await client.post(prefix + '/invoke', json=payload)
            assert pending.status_code == 200 and pending.json()['approval_required']
            approval_id = pending.json()['approval_id']
            assert runtime.store.transition_mcp_approval(approval_id, 'pending', 'approved')
            result = await client.post(prefix + '/invoke', json=payload)
            assert result.status_code == 200 and result.json()['status'] == 'completed'
        assert allowed.resolve() in captured_roots
        assert external.resolve() not in captured_roots
        monkeypatch.setenv('SECMIND_MCP_ROOTS', os.pathsep.join(map(str, captured_roots)))
        assert artifact_path(str(allowed)) == allowed.resolve()
        with pytest.raises(ValueError, match='authorized'):
            artifact_path(str(sibling))
    finally:
        await gateway.close()


async def test_burp_read_only_get_uses_scope_without_approval_and_preserves_old_request(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'read_only_http'
    state.task.target_scope = ['https://target.test/allowed/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-burp', 'name': 'Burp', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'send_http1_request', 'description': 'HTTP/1.1 request',
            'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'burp-get-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    arguments = {'targetHostname': 'target.test', 'targetPort': 443, 'usesHttps': True,
                 'content': 'GET /allowed/page HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n'}
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'burp-readonly-001', 'arguments': arguments}
            allowed = await client.post(prefix + '/invoke', json=payload)
            assert allowed.status_code == 200 and not allowed.json().get('approval_required')
            assert len(calls) == 1
            assert not runtime.store.pending_mcp_approvals('bridge-test')
            out_of_scope = await client.post(prefix + '/invoke', json={
                **payload, 'request_id': 'burp-readonly-002',
                'arguments': {**arguments, 'content': arguments['content'].replace('/allowed/page', '/admin')},
            })
            assert out_of_scope.status_code == 200 and out_of_scope.json()['approval_required']
            assert '授权范围' in '；'.join(runtime.store.mcp_approval(out_of_scope.json()['approval_id'])['policy_reasons'])
            assert len(calls) == 1
            assert (await client.post('/api/v1/mcp/approvals/' + out_of_scope.json()['approval_id'],
                                      json={'decision': 'approve'})).status_code == 200
            approved_scope = await client.post(prefix + '/invoke', json={
                **payload, 'request_id': 'burp-readonly-002',
                'arguments': {**arguments, 'content': arguments['content'].replace('/allowed/page', '/admin')},
            })
            assert approved_scope.status_code == 200 and len(calls) == 2
            assert (await client.post(prefix + '/invoke', json={
                **payload, 'request_id': 'burp-readonly-002',
                'arguments': {**arguments, 'content': arguments['content'].replace('/allowed/page', '/other')},
            })).status_code == 409
            old_key = 'bridge-test:proj-test:i001:burp-old-pending'
            runtime.store.request_mcp_approval(old_key, {
                'run_id': 'bridge-test', 'project_id': 'proj-test', 'intent_id': 'i001',
                'worker': 'worker-test', 'server_id': 'local-burp',
                'tool_name': 'send_http1_request', 'tool': spec['name'],
                'version': spec['version'], 'arguments': arguments,
                'arguments_sha256': hashlib.sha256(json.dumps(
                    arguments, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                ).encode('utf-8')).hexdigest(),
                'target': '', 'expected_impact': spec['description'], 'risk_level': 'R2',
            })
            old = await client.post(prefix + '/invoke', json={
                **payload, 'request_id': 'burp-old-pending',
            })
            assert old.status_code == 200 and old.json()['approval_required']
            assert len(calls) == 2
    finally:
        await gateway.close()


@pytest.mark.parametrize('policy', ['automatic', 'automatic_r3'])
async def test_global_read_only_mcp_query_follows_autonomy_policy(settings, monkeypatch, policy):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    state = service.ledger.load_state('bridge-test')
    state.task.autonomy_policy = policy
    state.task.network_policy = 'session_http'
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    server = {'server_id': 'local-yakit', 'name': 'Yak', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'get_mitm_filter', 'description': 'Read MITM capture filter',
            'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'read-only-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            spec = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'][0]
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'read-only-test-001', 'arguments': {},
            })
            assert response.status_code == 200
            if policy == 'automatic_r3':
                assert response.json()['status'] == 'completed'
                assert not response.json().get('approval_required')
                assert len(calls) == 1
            else:
                assert response.json()['status'] == 'pending'
                assert response.json()['approval_required']
                assert not calls
    finally:
        await gateway.close()


@pytest.mark.parametrize('policy,tool_name,approved', [
    ('graded', 'write_comment', False),
    ('approval_all', 'write_comment', False),
    ('automatic', 'write_comment', True),
    ('automatic_r3', 'write_comment', True),
    ('automatic', 'delete_http_flow', False),
    ('automatic_r3', 'delete_http_flow', True),
])
async def test_workbench_autonomy_skips_only_selected_risk_approval(
        settings, monkeypatch, policy, tool_name, approved):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    state = service.ledger.load_state('bridge-test')
    state.task.autonomy_policy = policy
    state.task.network_policy = 'read_only_http'
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    server = {'server_id': 'local-burp', 'name': 'Burp', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': tool_name, 'description': 'Test operation', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'autonomy-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            spec = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'][0]
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'autonomy-test-001', 'arguments': {'comment': 'fixture'},
            })
            assert response.status_code == 200
            assert bool(response.json().get('approval_required')) is not approved
            assert len(calls) == int(approved)
            assert bool(runtime.store.pending_mcp_approvals('bridge-test')) is not approved
    finally:
        await gateway.close()


@pytest.mark.parametrize('policy,risk,approval_required', [
    ('automatic', 'R2', False), ('automatic_r3', 'R2', False),
    ('automatic', 'R3', True), ('automatic_r3', 'R3', False),
])
async def test_yakit_fixed_scoped_http_uses_selected_autonomy(settings, monkeypatch, policy, risk, approval_required):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    state = service.ledger.load_state('bridge-test')
    state.task.autonomy_policy = policy
    state.task.network_policy = 'session_http'
    state.task.target_scope = ['https://target.test/allowed/']
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    server = {'server_id': 'local-yakit', 'name': 'Yak', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True, 'risk_level': risk}
    tool = {'name': 'http_fuzzer', 'description': 'HTTP request', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(kwargs)
        return {'status': 'completed', 'call_id': 'yakit-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    arguments = {'request': 'GET /allowed/page HTTP/1.1\r\nHost: target.test\r\n\r\n',
                 'isHttps': True, 'fuzzTagMode': 'close', 'noFollowRedirect': True,
                 'perRequestTimeoutSeconds': 10, 'repeatTimes': 1}
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            spec = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'yakit-fixed', 'arguments': arguments}
            response = await client.post(prefix + '/invoke', json=payload)
            assert response.status_code == 200
            assert bool(response.json().get('approval_required')) == approval_required
            assert len(calls) == int(not approval_required)
            if calls:
                assert calls[0].get('scope_override_approval_id') is None
            for index, overrides in enumerate([
                {'request': arguments['request'].replace('/allowed/page', '/admin')},
                {'request': arguments['request'].replace('target.test', 'outside.test')},
                {'fuzzTagMode': 'standard'}, {'noFollowRedirect': False},
                {'actualAddr': 'outside.test:443'},
            ]):
                reviewed = await client.post(prefix + '/invoke', json={
                    **payload, 'request_id': f'yakit-boundary-{index}',
                    'arguments': {**arguments, **overrides},
                })
                if policy == 'automatic_r3':
                    assert reviewed.status_code == 200 and reviewed.json()['status'] == 'completed'
                    assert not reviewed.json().get('approval_required')
                    assert len(calls) == index + 2
                    approval_id = calls[-1]['scope_override_approval_id']
                    assert runtime.store.mcp_approval(approval_id)['status'] == 'consumed'
                else:
                    assert reviewed.status_code == 200 and reviewed.json()['approval_required']
                    record = runtime.store.mcp_approval(reviewed.json()['approval_id'])
                    assert record['policy_reasons']
                    assert len(calls) == int(not approval_required)
    finally:
        await gateway.close()


@pytest.mark.parametrize('policy', ['automatic', 'automatic_r3'])
async def test_target_scope_exception_follows_autonomy_policy(settings, monkeypatch, policy):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    state = service.ledger.load_state('bridge-test')
    state.task.autonomy_policy = policy
    state.task.network_policy = 'read_only_http'
    state.task.target_scope = ['https://target.test/allowed/']
    state.external_execution['blackboard'] = {'planning_mode': 'workbench', 'project_id': 'proj-test'}
    service.ledger.save_state(state)
    server = {'server_id': 'local-tscanplus', 'name': 'Tscan', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(kwargs)
        return {'status': 'completed', 'call_id': 'scope-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            spec = (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).json()['tools'][0]
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'out-of-scope-001',
                'arguments': {'url': 'https://elsewhere.test/', 'method': 'GET'},
            })
            if policy == 'automatic_r3':
                assert response.status_code == 200 and response.json()['status'] == 'completed'
                assert len(calls) == 1
                approval_id = calls[0]['scope_override_approval_id']
                record = runtime.store.mcp_approval(approval_id)
                assert record['status'] == 'consumed'
                assert any('授权范围' in reason for reason in record['policy_reasons'])
                assert not runtime.store.pending_mcp_approvals('bridge-test')
            else:
                assert response.status_code == 200 and response.json()['approval_required']
                record = runtime.store.mcp_approval(response.json()['approval_id'])
                assert any('授权范围' in reason for reason in record['policy_reasons'])
                assert not calls
    finally:
        await gateway.close()


async def test_destructive_mcp_tool_requires_explicit_approval(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-yakit', 'name': 'Yak', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'delete_http_flow', 'description': 'Delete flow',
            'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []
    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'destructive-fixture'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'destructive-test-001', 'arguments': {},
            })
            assert response.status_code == 200 and response.json()['approval_required']
            record = runtime.store.mcp_approval(response.json()['approval_id'])
            assert record['risk_level'] == 'R3'
            assert record['approval_type'] == '高风险操作'
            assert calls == []
            assert (await client.post('/api/v1/mcp/approvals/' + record['approval_id'],
                                      json={'decision': 'approve'})).status_code == 200
            completed = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'destructive-test-001', 'arguments': {},
            })
            assert completed.status_code == 200 and completed.json()['status'] == 'completed'
            assert len(calls) == 1
            replay = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'destructive-test-001', 'arguments': {},
            })
            assert replay.status_code == 409 and len(calls) == 1
    finally:
        await gateway.close()


async def test_worker_bridge_calls_real_stdio_mcp_and_records_blackboard_receipt(settings, monkeypatch):
    service, gateway, detail, transport, bridge = await setup_bridge(settings, monkeypatch)
    try:
        async with create_connected_server_and_client_session(bridge) as session:
            tools = await session.list_tools()
            tool = next(t for t in tools.tools if 'decode_base64' in t.description)
            result = await session.call_tool(tool.name, {'text': 'aGVsbG8='})
            assert not result.isError
            assert 'hello' in result.content[0].text
            receipt = service.orchestrator.mcp_runtime.store.recent('mcp')[0]
            assert receipt['run_id'] == 'bridge-test'
            assert receipt['blackboard'] == {'project_id': 'proj-test', 'intent_id': 'i001', 'worker': 'worker-test'}
            artifact = settings.run_root / '.mcp-results' / (receipt['call_id'] + '.json')
            assert json.loads(artifact.read_text(encoding='utf-8')) == receipt
            assert service.ledger.verify('bridge-test')
            failed = await session.call_tool(tool.name, {'text': '!invalid!'})
            assert failed.isError
            assert 'failed' in failed.content[0].text
            count = len(service.orchestrator.mcp_runtime.store.recent('mcp'))
            detail['project']['status'] = 'stopped'
            stopped = await session.call_tool(tool.name, {'text': 'aGVsbG8='})
            assert stopped.isError
            assert len(service.orchestrator.mcp_runtime.store.recent('mcp')) == count
    finally:
        await gateway.close()


async def test_dispatcher_worker_can_use_coordinator_bound_project(settings, monkeypatch):
    """A dispatcher lease may use its assigned worker after coordinator setup."""
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.external_execution['blackboard'] = {
        'backend': 'remote',
        'project_id': 'proj-test',
        'worker': 'unified-workbench:bridge-test',
        'status': 'entered',
    }
    service.ledger.save_state(state)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            response = await client.get(
                '/api/v1/mcp/blackboard/proj-test/i001/tools',
                params={'worker': 'worker-test'},
            )
        assert response.status_code == 200
        assert response.json()['tools']
    finally:
        await gateway.close()


@pytest.mark.parametrize('method', ['GET', 'HEAD'])
async def test_penetration_bridge_allows_only_scoped_read_only_http(settings, monkeypatch, method):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'read_only_http'
    state.task.target_scope = ['https://target.test/allowed/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    http_tool = {'name': 'http_request', 'description': 'HTTP request',
                 'inputSchema': {'type': 'object', 'properties': {'url': {'type': 'string'}}}}
    scan_tool = {'name': 'url_scan', 'description': 'URL scan', 'inputSchema': {'type': 'object'}}
    original = list(runtime.agent_tools())
    local_tool = {'name': 'decode_base64', 'description': 'decode_base64',
                  'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([
        *original, (runtime.builtin(), local_tool), (server, http_tool), (server, scan_tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        calls.append((args, kwargs))
        return {'status': 'completed', 'call_id': 'fixture-call'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            assert listed.status_code == 200
            assert any('decode_base64' in item['description'] for item in listed.json()['tools'])
            assert any('url_scan' in item['description'] for item in listed.json()['tools'])
            spec = next(item for item in listed.json()['tools'] if 'http_request' in item['description'])
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'arguments': {'url': 'https://target.test/allowed/page', 'method': method,
                                     'follow_redirect': False}}
            allowed = await client.post(prefix + '/invoke', json=payload)
            assert allowed.status_code == 200
            assert calls[-1][0][1] == 'http_request'
            for index, arguments in enumerate([
                {**payload['arguments'], 'method': 'POST'},
                {**payload['arguments'], 'body': 'data'},
                {**payload['arguments'], 'follow_redirect': True},
                {**payload['arguments'], 'headers': 'Host: outside.test'},
                {**payload['arguments'], 'url': 'https://outside.test/'},
            ]):
                pending = await client.post(prefix + '/invoke', json={**payload,
                    'request_id': f'http-exception-{index:03d}', 'arguments': arguments})
                assert pending.status_code == 200 and pending.json()['approval_required']
            assert len(calls) == 1
            state = service.ledger.load_state('bridge-test')
            state.status = RunStatus.PARTIAL
            service.ledger.save_state(state)
            assert (await client.get(prefix + '/tools', params={'worker': 'worker-test'})).status_code == 409
            assert (await client.post(prefix + '/invoke', json=payload)).status_code == 409
            assert len(calls) == 1
    finally:
        await gateway.close()


async def test_penetration_bridge_static_policy_lists_but_blocks_network_tools(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request', 'inputSchema': {'type': 'object'}}
    original = list(runtime.agent_tools())
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([*original, (server, tool)]))
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools',
                                      params={'worker': 'worker-test'})
            assert listed.status_code == 200
            spec = next(item for item in listed.json()['tools'] if 'http_request' in item['description'])
            denied = await client.post('/api/v1/mcp/blackboard/proj-test/i001/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'arguments': {'url': 'https://target.test/'}, 'request_id': 'offline-network-001',
            })
        assert denied.status_code == 200 and denied.json()['approval_required']
    finally:
        await gateway.close()


async def test_session_http_rejects_cookie_injection_and_flags_wrong_host(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'session_http'
    state.task.target_scope = ['https://target.test/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'arguments': {'url': 'https://target.test/', 'method': 'GET'},
                       'request_id': 'session-header-001'}
            injected = await client.post(prefix + '/invoke', json={
                **payload, 'arguments': {**payload['arguments'],
                                         'cookie': 'session=x\r\nHost: outside.test'}})
            assert injected.status_code == 422
            assert not runtime.store.pending_mcp_approvals('bridge-test')
            wrong_host = await client.post(prefix + '/invoke', json={
                **payload, 'arguments': {**payload['arguments'], 'headers': 'Host: outside.test'}})
            assert wrong_host.status_code == 200 and wrong_host.json()['approval_required']
            approval = runtime.store.mcp_approval(wrong_host.json()['approval_id'])
            assert any('Host 请求头与目标 URL 不一致' in reason for reason in approval['policy_reasons'])
    finally:
        await gateway.close()


async def test_tscanplus_relative_dictionary_path_cannot_be_approved(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'dir_scan', 'description': 'Directory scan', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'arguments': {'urls': ['https://target.test/'], 'dict': 'words.txt'},
                'request_id': 'relative-dictionary-001',
            })
            assert response.status_code == 422
            assert '绝对路径' in response.json()['detail']
            assert not runtime.store.pending_mcp_approvals('bridge-test')
    finally:
        await gateway.close()


async def test_scoped_post_bridge_checks_grant_body_and_intent_budget(settings, monkeypatch):
    import json
    target = 'https://target.test/'
    grant = Grant(SCOPED_POST_SOURCE_RUN_ID, target, SCOPED_POST_REQUEST_ID)
    grant_path(settings).parent.mkdir(parents=True, exist_ok=True)
    grant_path(settings).write_text(json.dumps({
        'source_run_id': grant.source_run_id, 'target_url': target,
        'request_id': grant.request_id,
    }), encoding='utf-8')
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch, grant.child_run_id)
    state = service.ledger.load_state(grant.child_run_id)
    state.retry_of = grant.source_run_id
    state.budget.max_tool_calls = 60
    state.task.target_scope = [target]
    state.task.network_policy = SCOPED_POST_POLICY
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request',
            'inputSchema': {'type': 'object', 'properties': {'url': {'type': 'string'}}}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        return {'status': 'completed', 'call_id': 'fixture-call'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            assert listed.status_code == 200
            spec = listed.json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'arguments': {'url': target, 'method': 'POST', 'body': 'file=index.php',
                                     'follow_redirect': False}}
            for index, arguments in enumerate([
                {**payload['arguments'], 'url': target + 'other'},
                {**payload['arguments'], 'method': 'PUT'},
                {**payload['arguments'], 'body': 'file=php%3A%2F%2Finput'},
                {**payload['arguments'], 'body': 'file=x&other=y'},
                {**payload['arguments'], 'headers': 'X-Test: value'},
                {**payload['arguments'], 'cookie': 'session=x'},
                {**payload['arguments'], 'follow_redirect': True},
            ]):
                pending = await client.post(prefix + '/invoke', json={
                    **payload, 'request_id': f'post-exception-{index:03d}', 'arguments': arguments})
                assert pending.status_code == 200 and pending.json()['approval_required']
            for index in range(40):
                approved_payload = {**payload, 'request_id': f'scoped-post-{index:03d}'}
                pending = await client.post(prefix + '/invoke', json=approved_payload)
                assert pending.status_code == 200 and pending.json()['approval_required']
                approval_id = pending.json()['approval_id']
                assert runtime.store.transition_mcp_approval(approval_id, 'pending', 'approved')
                assert (await client.post(prefix + '/invoke', json=approved_payload)).status_code == 200
            over_budget = {**payload, 'request_id': 'scoped-post-over-budget'}
            pending = await client.post(prefix + '/invoke', json=over_budget)
            assert pending.status_code == 200 and pending.json()['approval_required']
            assert runtime.store.transition_mcp_approval(pending.json()['approval_id'], 'pending', 'approved')
            assert (await client.post(prefix + '/invoke', json=over_budget)).status_code == 409
            for _ in range(20):
                assert runtime.store.reserve_blackboard_call(
                    grant.child_run_id, 'i002', run_limit=60, intent_limit=40)
            assert not runtime.store.reserve_blackboard_call(
                grant.child_run_id, 'i002', run_limit=60, intent_limit=40)
            state.status = RunStatus.PARTIAL
            service.ledger.save_state(state)
            assert (await client.post(prefix + '/invoke', json=payload)).status_code == 409
    finally:
        await gateway.close()


async def test_bounded_http_policy_keeps_kali_scanners_available(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = BOUNDED_HTTP_POLICY
    state.task.target_scope = ['https://target.test/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    kali = runtime.kali_builtin()
    nmap = {'name': 'nmap_scan', 'description': 'nmap_scan', 'inputSchema': {'type': 'object'}}
    version_tool = {'name': 'kali_tool_version', 'description': 'kali_tool_version',
                    'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(kali, nmap), (kali, version_tool)]))

    async def no_refresh():
        return None

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools',
                                      params={'worker': 'worker-test'})
        assert listed.status_code == 200
        descriptions = [item['description'] for item in listed.json()['tools']]
        assert any('nmap_scan' in item for item in descriptions)
    finally:
        await gateway.close()


async def test_read_only_http_policy_still_keeps_kali_scanners_available(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'read_only_http'
    state.task.target_scope = ['https://target.test/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    kali = runtime.kali_builtin()
    nmap = {'name': 'nmap_scan', 'description': 'nmap_scan', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(kali, nmap)]))

    async def no_refresh():
        return None

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools',
                                      params={'worker': 'worker-test'})
        assert listed.status_code == 200
        assert any('nmap_scan' in item['description'] for item in listed.json()['tools'])
    finally:
        await gateway.close()


async def test_static_policy_lists_kali_scanners_but_blocks_calls(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = 'none'
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    kali = runtime.kali_builtin()
    nmap = {'name': 'nmap_scan', 'description': 'nmap_scan', 'inputSchema': {'type': 'object'}}
    version_tool = {'name': 'kali_tool_version', 'description': 'kali_tool_version',
                    'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(kali, nmap), (kali, version_tool)]))

    async def no_refresh():
        return None

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools',
                                      params={'worker': 'worker-test'})
        assert listed.status_code == 200
        descriptions = [item['description'] for item in listed.json()['tools']]
        assert any('nmap_scan' in item for item in descriptions)
        assert any('kali_tool_version' in item for item in descriptions)
    finally:
        await gateway.close()


async def test_blackboard_request_id_replays_receipt_without_second_tool_call(settings, monkeypatch):
    settings.blackboard_max_mcp_calls_per_run = 1
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            assert listed.status_code == 200
            spec = next(tool for tool in listed.json()['tools'] if 'decode_base64' in tool['description'])
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'same-request-001', 'arguments': {'text': 'aGVsbG8='}}
            first = await client.post(prefix + '/invoke', json=payload)
            replay = await client.post(prefix + '/invoke', json=payload)
            assert first.status_code == replay.status_code == 200
            assert first.json()['status'] == 'completed'
            assert replay.json() == first.json()
            assert len(runtime.store.recent('mcp')) == 1
            assert len([event for event in service.ledger.events('bridge-test')
                        if event.event_type == 'mcp.call.completed']) == 1
            changed = await client.post(prefix + '/invoke', json={
                **payload, 'arguments': {'text': 'd29ybGQ='},
            })
            assert changed.status_code == 409
            assert len(runtime.store.recent('mcp')) == 1
    finally:
        await gateway.close()


async def test_blackboard_concurrent_replay_waits_for_terminal_receipt(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    class Session:
        async def call_tool(self, name, arguments):
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            return CallToolResult(content=[])

    @asynccontextmanager
    async def fake_session(server, *, allowed_roots=None):
        yield Session()

    async def fake_tools(session):
        return [{'name': 'decode_base64', 'description': 'test',
                 'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}},
                                 'required': ['text']}}]

    monkeypatch.setattr(runtime, 'session', fake_session)
    monkeypatch.setattr(runtime, '_tools', fake_tools)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = next(item for item in listed.json()['tools'] if 'decode_base64' in item['description'])
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'concurrent-replay-001', 'arguments': {'text': 'aGVsbG8='}}
            first = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await entered.wait()
            replay = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await asyncio.sleep(0.1)
            assert not replay.done()
            release.set()
            first_response, replay_response = await asyncio.gather(first, replay)
            assert first_response.status_code == replay_response.status_code == 200
            assert first_response.json() == replay_response.json()
            assert first_response.json()['status'] == 'completed'
            assert calls == 1
            assert len(runtime.store.recent('mcp')) == 1
    finally:
        release.set()
        await gateway.close()


async def test_consumed_approval_replay_waits_for_terminal_receipt(settings, monkeypatch):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request', 'inputSchema': {'type': 'object'}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = listed.json()['tools'][0]
            payload = {'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                       'request_id': 'consumed-replay-001',
                       'arguments': {'url': 'https://target.test/', 'method': 'GET'}}
            pending = await client.post(prefix + '/invoke', json=payload)
            assert pending.json()['approval_required']
            approval_id = pending.json()['approval_id']
            assert runtime.store.transition_mcp_approval(approval_id, 'pending', 'consumed')
            request_key = 'bridge-test:i001:consumed-replay-001'
            receipt = {'call_id': 'fixed-call-id', 'server_id': 'local-tscanplus',
                       'tool': 'http_request', 'arguments': payload['arguments'],
                       'run_id': 'bridge-test', 'status': 'running', 'idempotency_key': request_key}
            claimed, _ = runtime.store.claim_mcp_request(request_key, receipt['call_id'], receipt)
            assert claimed
            replay = asyncio.create_task(client.post(prefix + '/invoke', json=payload))
            await asyncio.sleep(0.1)
            assert not replay.done()
            receipt.update(status='completed', completed_at='2026-10-14T00:00:00+00:00')
            runtime.store.finish_mcp_call(receipt)
            response = await replay
            assert response.status_code == 200
            assert response.json() == receipt
    finally:
        await gateway.close()


async def test_blackboard_local_file_tool_cannot_read_another_run(settings, monkeypatch):
    service, gateway, _, transport, bridge = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    own = settings.run_root / 'bridge-test' / 'workspace' / 'own.txt'
    own.write_text('authorized material', encoding='utf-8')
    foreign = settings.run_root / 'other-run' / 'workspace' / 'foreign.txt'
    foreign.parent.mkdir(parents=True)
    foreign.write_text('another task material', encoding='utf-8')
    try:
        assert state.workspace == str(own.parent)
        async with create_connected_server_and_client_session(bridge) as session:
            tools = await session.list_tools()
            tool = next(item for item in tools.tools if 'hash_file' in item.description)
            allowed = await session.call_tool(tool.name, {'path': str(own)})
        assert not allowed.isError
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools',
                                      params={'worker': 'worker-test'})
            spec = next(item for item in listed.json()['tools'] if 'hash_file' in item['description'])
            pending = await client.post('/api/v1/mcp/blackboard/proj-test/i001/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'foreign-file-001', 'arguments': {'path': str(foreign)},
            })
            assert pending.status_code == 200 and pending.json()['approval_required']
            assert service.orchestrator.mcp_runtime.store.recent('mcp')[0]['status'] == 'completed'
            approved = await client.post('/api/v1/mcp/approvals/' + pending.json()['approval_id'],
                                         json={'decision': 'approve'})
            assert approved.status_code == 200
            completed = await client.post('/api/v1/mcp/blackboard/proj-test/i001/invoke', json={
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'request_id': 'foreign-file-001', 'arguments': {'path': str(foreign)},
            })
            assert completed.status_code == 200 and completed.json()['status'] == 'completed'
        receipts = service.orchestrator.mcp_runtime.store.recent('mcp')
        assert [item['status'] for item in receipts] == ['completed', 'completed']
        assert service.ledger.verify('bridge-test')
    finally:
        await gateway.close()


@pytest.mark.parametrize('change', [
    'worker', 'concluded', 'project', 'run', 'plan', 'title', 'project_id',
    'unconfirmed', 'workspace', 'missing_workspace',
])
async def test_bridge_rejects_inactive_or_unassigned_work(settings, monkeypatch, change):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    try:
        if change == 'worker':
            detail['intents'][0]['worker'] = 'different-worker'
        elif change == 'concluded':
            detail['intents'][0]['concluded_at'] = '2026-10-03T00:00:00Z'
        elif change == 'project':
            detail['project']['status'] = 'completed'
        elif change == 'title':
            detail['project']['title'] = 'unrelated'
        elif change == 'project_id':
            state = service.ledger.load_state('bridge-test')
            state.external_execution['project_id'] = 'actual-submitted-project'
            service.ledger.save_state(state)
        elif change == 'unconfirmed':
            state = service.ledger.load_state('bridge-test')
            state.external_execution = {'module': 'penetration', 'status': 'submitting'}
            service.ledger.save_state(state)
        elif change == 'workspace':
            state = service.ledger.load_state('bridge-test')
            other = settings.run_root / 'other-run' / 'workspace'
            other.mkdir(parents=True)
            state.workspace = str(other)
            service.ledger.save_state(state)
        elif change == 'missing_workspace':
            state = service.ledger.load_state('bridge-test')
            state.workspace = str(settings.run_root / 'bridge-test' / 'missing')
            service.ledger.save_state(state)
        else:
            state = service.ledger.load_state('bridge-test')
            if change == 'run':
                state.status = RunStatus.COMPLETED
            else:
                state.plan[0].tool_candidates = ['mcp:secmind-local:decode_base64']
            service.ledger.save_state(state)
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            response = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools', params={'worker': 'worker-test'})
            assert response.status_code == 409
        assert not service.orchestrator.mcp_runtime.store.recent('mcp')
    finally:
        await gateway.close()


async def test_bridge_enforces_protocol_version_and_revocation(settings, monkeypatch):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            response = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            tool = next(t for t in response.json()['tools'] if 'decode_base64' in t['description'])
            response = await client.post(prefix + '/invoke', json={'worker': 'worker-test',
                'tool': tool['name'], 'version': 'stale', 'arguments': {'text': 'aGVsbG8='}})
            assert response.status_code == 409
            with pytest.raises(ValueError, match='黑板'):
                await service.orchestrator.mcp_runtime.invoke('secmind-local', 'decode_base64',
                    {'text': 'aGVsbG8='}, approved=True, run_id='bridge-test')
            assert not service.orchestrator.mcp_runtime.store.recent('mcp')
    finally:
        await gateway.close()


@pytest.mark.parametrize('error,expected', [
    (ValueError('MCP request_id 已用于不同的工具调用'), 'MCP request_id 已用于不同的工具调用'),
    (OSError('fixture unavailable'), '黑板任务工作区不可用'),
])
async def test_bridge_preserves_invocation_validation_error(settings, monkeypatch, error, expected):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime

    async def fail_invoke(*args, **kwargs):
        raise error

    monkeypatch.setattr(runtime, 'invoke', fail_invoke)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            tool = next(item for item in listed.json()['tools'] if 'decode_base64' in item['description'])
            response = await client.post(prefix + '/invoke', json={
                'worker': 'worker-test', 'tool': tool['name'], 'version': tool['version'],
                'arguments': {'text': 'aGVsbG8='}, 'request_id': 'error-reason-001',
            })
            assert response.status_code == 409
            assert response.json()['detail'] == expected
    finally:
        await gateway.close()


@pytest.mark.parametrize('payload', [
    {}, {'worker': [], 'tool': {}, 'version': 'v'},
    {'worker': 'worker-test', 'tool': 'x', 'version': 'v', 'arguments': []},
    {'worker': 'worker-test', 'tool': 'x', 'version': 'v', 'approved': True},
])
async def test_bridge_malformed_request_is_422_not_500(settings, monkeypatch, payload):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            response = await client.post('/api/v1/mcp/blackboard/proj-test/i001/invoke', json=payload)
        assert response.status_code == 422
        assert not service.orchestrator.mcp_runtime.store.recent('mcp')
    finally:
        await gateway.close()


@pytest.mark.parametrize('detail', [[], {'project': None},
    {'project': {'title': None}, 'intents': []},
    {'project': {'title': 'sec-task-bridge-test'}, 'intents': None},
    {'project': {'id': 'proj-test', 'title': 'sec-task-bridge-test', 'status': 'active'}, 'intents': [None]},
])
async def test_invalid_blackboard_reply_blocks_tools(settings, monkeypatch, detail):
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)

    async def invalid_reply(*args):
        return detail

    monkeypatch.setattr('security_agent.blackboard_mcp.penetration_get', invalid_reply)
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            response = await client.get('/api/v1/mcp/blackboard/proj-test/i001/tools', params={'worker': 'worker-test'})
        assert response.status_code == 409
        assert not service.orchestrator.mcp_runtime.store.recent('mcp')
    finally:
        await gateway.close()


@pytest.mark.parametrize('change', ['stop', 'reassign'])
async def test_assignment_changed_during_connection_never_reaches_tool(settings, monkeypatch, change):
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/i001'
            response = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            spec = next(t for t in response.json()['tools'] if 'decode_base64' in t['description'])
            discovered = [tool for _, tool in runtime.agent_tools()]

            class Session:
                async def call_tool(self, *args):
                    pytest.fail('Revoked assignment reached tools/call')

            @asynccontextmanager
            async def connecting(server, **kwargs):
                if change == 'stop':
                    detail['project']['status'] = 'stopped'
                else:
                    detail['intents'][0]['worker'] = 'replacement-worker'
                yield Session()

            async def tools(session):
                return discovered

            monkeypatch.setattr(runtime, 'session', connecting)
            monkeypatch.setattr(runtime, '_tools', tools)
            response = await client.post(prefix + '/invoke', json={'worker': 'worker-test',
                'tool': spec['name'], 'version': spec['version'], 'arguments': {'text': 'aGVsbG8='}})
        assert response.status_code == 200
        assert response.json()['status'] == 'failed'
        assert '409' in response.json()['error']
        assert service.ledger.verify('bridge-test')
    finally:
        await gateway.close()


async def test_expired_runtime_intent_lease_revokes_workbench_tools(settings, monkeypatch, tmp_path):
    # Exercise the actual Security Runtime router and SQLite lease expiry,
    # instead of supplying a hand-written project detail to the bridge.
    runtime_src = Path(__file__).parents[2] / 'security-runtime' / 'security-runtime' / 'src'
    monkeypatch.syspath_prepend(str(runtime_src))
    from security_runtime.server import db
    from security_runtime.server.app import app as runtime_app

    monkeypatch.setattr(db, '_db_path', None)
    db.configure(tmp_path / 'security-runtime.db')
    service, gateway, _, workbench_transport, _ = await setup_bridge(settings, monkeypatch)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime_app),
                                     base_url='http://localhost') as runtime_client:
            created = await runtime_client.post('/projects', json={
                'title': 'sec-task-bridge-test', 'origin': 'authorized fixture',
                'goal': 'decode fixture', 'bootstrap_enabled': False,
            })
            assert created.status_code == 201
            project_id = created.json()['project']['id']
            claimed = await runtime_client.post(f'/projects/{project_id}/intents', json={
                'from': ['origin'], 'description': 'decode fixture',
                'creator': 'worker-test', 'worker': 'worker-test',
            })
            assert claimed.status_code == 201
            intent_id = claimed.json()['id']

            state = service.ledger.load_state('bridge-test')
            state.external_execution['project_id'] = project_id
            service.ledger.save_state(state)

            async def get_live_detail(_base_url, path, _timeout):
                response = await runtime_client.get(path)
                response.raise_for_status()
                return response.json()

            monkeypatch.setattr('security_agent.blackboard_mcp.penetration_get', get_live_detail)
            prefix = f'/api/v1/mcp/blackboard/{project_id}/{intent_id}'
            async with httpx.AsyncClient(transport=workbench_transport,
                                         base_url='http://workbench.test') as workbench_client:
                available = await workbench_client.get(prefix + '/tools', params={'worker': 'worker-test'})
                assert available.status_code == 200
                spec = next(item for item in available.json()['tools'] if 'decode_base64' in item['description'])
                payload = {
                    'worker': 'worker-test', 'tool': spec['name'],
                    'version': spec['version'], 'arguments': {'text': 'aGVsbG8='},
                }
                active_call = await workbench_client.post(prefix + '/invoke', json=payload)
                assert active_call.status_code == 200
                assert active_call.json()['status'] == 'completed'

                with db.get_conn() as conn:
                    conn.execute(
                        "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' "
                        'WHERE project_id = ? AND id = ?', (project_id, intent_id),
                    )
                expired = await runtime_client.get(f'/projects/{project_id}')
                assert expired.status_code == 200
                assert expired.json()['intents'][0]['worker'] is None

                denied_list = await workbench_client.get(prefix + '/tools', params={'worker': 'worker-test'})
                denied_call = await workbench_client.post(prefix + '/invoke', json=payload)
                assert denied_list.status_code == denied_call.status_code == 409
            assert len(service.orchestrator.mcp_runtime.store.recent('mcp')) == 1
    finally:
        await gateway.close()


@pytest.mark.parametrize('scope', ['run', 'intent'])
async def test_blackboard_call_budget_is_atomic_and_survives_restart(settings, monkeypatch, scope):
    settings.blackboard_max_mcp_calls_per_run = 1 if scope == 'run' else 2
    settings.blackboard_max_mcp_calls_per_intent = 2 if scope == 'run' else 1
    service, gateway, detail, transport, _ = await setup_bridge(settings, monkeypatch)
    runtime = service.orchestrator.mcp_runtime
    calls = []
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            prefix = '/api/v1/mcp/blackboard/proj-test/'
            response = await client.get(prefix + 'i001/tools', params={'worker': 'worker-test'})
            spec = next(t for t in response.json()['tools'] if 'decode_base64' in t['description'])
            discovered = [tool for _, tool in runtime.agent_tools()]

            class Session:
                async def call_tool(self, *args):
                    calls.append(args)
                    await asyncio.sleep(0)
                    return CallToolResult(content=[])

            @asynccontextmanager
            async def connecting(_server, **kwargs):
                yield Session()

            async def tools(_session):
                return discovered

            monkeypatch.setattr(runtime, 'session', connecting)
            monkeypatch.setattr(runtime, '_tools', tools)
            payload = {'worker': 'worker-test', 'tool': spec['name'],
                       'version': spec['version'], 'arguments': {'text': 'aGVsbG8='}}
            detail['intents'].append({'id': 'i002', 'worker': 'worker-test', 'to': None, 'concluded_at': None})
            paths = ['i001', 'i002'] if scope == 'run' else ['i001', 'i001']
            responses = await asyncio.gather(*(client.post(prefix + intent + '/invoke', json=payload)
                                                for intent in paths))
            assert sorted(response.json()['status'] for response in responses) == ['completed', 'failed']
            assert len(calls) == 1
            assert any('预算' in response.json().get('error', '') for response in responses)

            # Opening the database afresh models another workbench process.
            reopened = OperationsStore(runtime.store.path)
            exhausted_intent = 'i001' if scope == 'intent' else 'i002'
            assert not reopened.reserve_blackboard_call(
                'bridge-test', exhausted_intent,
                run_limit=settings.blackboard_max_mcp_calls_per_run,
                intent_limit=settings.blackboard_max_mcp_calls_per_intent,
            )
            if scope == 'intent':
                response = await client.post(prefix + 'i002/invoke', json=payload)
                assert response.json()['status'] == 'completed'
                assert len(calls) == 2
        assert service.ledger.verify('bridge-test')
    finally:
        await gateway.close()


def test_blackboard_call_budget_is_unbounded_when_limits_are_unset(tmp_path):
    """The Cairn-style default keeps accounting without a call-count stop."""
    store = OperationsStore(tmp_path / 'mcp-runtime.db')
    for _ in range(250):
        assert store.reserve_blackboard_call(
            'run-unbounded', 'i001', run_limit=None, intent_limit=None,
        )


async def test_bounded_http_bridge_allows_bounded_body_and_rejects_the_rest(settings, monkeypatch):
    """RFI-class tasks need one body-carrying request, nothing wider."""
    service, gateway, _, transport, _ = await setup_bridge(settings, monkeypatch)
    state = service.ledger.load_state('bridge-test')
    state.task.network_policy = BOUNDED_HTTP_POLICY
    state.task.target_scope = ['https://target.test/']
    service.ledger.save_state(state)
    runtime = service.orchestrator.mcp_runtime
    server = {'server_id': 'local-tscanplus', 'name': 'TscanPlus', 'transport': 'stdio',
              'command': 'fixture', 'args': [], 'enabled': True}
    tool = {'name': 'http_request', 'description': 'HTTP request',
            'inputSchema': {'type': 'object', 'properties': {'url': {'type': 'string'}}}}
    monkeypatch.setattr(runtime, 'agent_tools', lambda: iter([(server, tool)]))

    async def no_refresh():
        return None

    calls = []

    async def invoke(*args, **kwargs):
        await kwargs['before_call']()
        calls.append(args)
        return {'status': 'completed', 'call_id': 'fixture-call'}

    monkeypatch.setattr(runtime, 'refresh_agent_tools', no_refresh)
    monkeypatch.setattr(runtime, 'invoke', invoke)
    prefix = '/api/v1/mcp/blackboard/proj-test/i001'
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://workbench.test') as client:
            listed = await client.get(prefix + '/tools', params={'worker': 'worker-test'})
            assert listed.status_code == 200
            spec = next(item for item in listed.json()['tools'] if 'http_request' in item['description'])
            allowed = {
                'worker': 'worker-test', 'tool': spec['name'], 'version': spec['version'],
                'arguments': {
                    'url': 'https://target.test/?path=PHp://input', 'method': 'POST',
                    'body': "<?php system('cat /var/www/html/flag.php'); ?>",
                    'follow_redirect': False,
                },
            }
            allowed['request_id'] = 'bounded-post-001'
            pending = await client.post(prefix + '/invoke', json=allowed)
            assert pending.status_code == 200 and pending.json()['approval_required']
            assert runtime.store.transition_mcp_approval(pending.json()['approval_id'], 'pending', 'approved')
            assert (await client.post(prefix + '/invoke', json=allowed)).status_code == 200
            assert len(calls) == 1
            for arguments in [
                {**allowed['arguments'], 'method': 'PUT'},
                {**allowed['arguments'], 'body': 'x' * 4097},
                {**allowed['arguments'], 'follow_redirect': True},
                {**allowed['arguments'], 'headers': 'Host: outside.test'},
                {**allowed['arguments'], 'cookie': 'session=x'},
                {**allowed['arguments'], 'url': 'https://outside.test/'},
            ]:
                denied = await client.post(prefix + '/invoke', json={**allowed, 'arguments': arguments})
                assert denied.status_code in {403, 409}, arguments
            assert len(calls) == 1
    finally:
        await gateway.close()
