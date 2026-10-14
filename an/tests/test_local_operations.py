import asyncio
import hashlib
import json
import sqlite3
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from security_agent.api import create_app
from security_agent.incident_response import IncidentManager
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelGateway
from security_agent.mcp_catalog import MCPCatalog
from security_agent.mcp_runtime import MCPRuntime
from security_agent.runtime_prompts import RuntimePrompts
from security_agent.schemas import AgentState, TaskRequest


async def test_quarantine_persists_approval_and_restores_exact_bytes(tmp_path):
    manager = IncidentManager(tmp_path / 'ir')
    sample = manager.root / 'samples' / 'sample.txt'
    content = b'harmless regression sample\x00\xff'
    sample.write_bytes(content)
    submitted = await manager.submit_command('isolate_sample', str(sample))
    assert sample.read_bytes() == content
    # Pending approval survives a restart.
    manager = IncidentManager(manager.root)
    approved = await manager.resolve_approval(submitted['approval']['approval_id'], 'approve')
    assert approved['action']['status'] == 'completed'
    assert not sample.exists()
    quarantine_id = approved['action']['result']['id']
    assert (manager.root / 'quarantine' / quarantine_id / 'sample.bin').read_bytes() == content
    restore = await manager.submit_command('restore_snapshot', quarantine_id)
    result = await manager.resolve_approval(restore['approval']['approval_id'], 'approve')
    assert result['action']['status'] == 'completed'
    assert sample.read_bytes() == content
    with pytest.raises(ValueError, match='审批已处理'):
        await manager.resolve_approval(restore['approval']['approval_id'], 'approve')
    assert IncidentManager(manager.root).quarantines()[0]['status'] == 'restored'


async def test_approval_cannot_hide_file_change_or_overwrite_restore(tmp_path):
    manager = IncidentManager(tmp_path / 'ir')
    sample = manager.root / 'samples' / 'sample.txt'
    sample.write_text('before')
    action = await manager.submit_command('isolate_sample', str(sample))
    sample.write_text('after')
    failed = await manager.resolve_approval(action['approval']['approval_id'], 'approve')
    assert failed['action']['status'] == 'failed'
    assert sample.read_text() == 'after'
    action = await manager.submit_command('isolate_sample', str(sample))
    approved = await manager.resolve_approval(action['approval']['approval_id'], 'approve')
    sample.write_text('replacement')
    restore = await manager.submit_command('restore_snapshot', approved['action']['result']['id'])
    failed = await manager.resolve_approval(restore['approval']['approval_id'], 'approve')
    assert failed['action']['status'] == 'failed'
    assert sample.read_text() == 'replacement'


async def test_unknown_commands_and_outside_files_are_rejected(tmp_path):
    manager = IncidentManager(tmp_path / 'ir')
    outside = tmp_path / 'private.txt'
    outside.write_text('do not touch')
    with pytest.raises(ValueError):
        await manager.submit_command('shell command', 'local')
    with pytest.raises(ValueError):
        await manager.submit_command('isolate_sample', str(outside))
    with pytest.raises(ValueError):
        await manager.submit_command('scan_assets', 'remote.example')
    assert outside.read_text() == 'do not touch'


async def test_concurrent_approval_executes_only_once(tmp_path):
    manager = IncidentManager(tmp_path / 'ir')
    sample = manager.root / 'samples' / 'sample.txt'
    sample.write_text('test')
    pending = await manager.submit_command('isolate_sample', str(sample))
    results = await asyncio.gather(*[manager.resolve_approval(pending['approval']['approval_id'], 'approve') for _ in range(2)], return_exceptions=True)
    assert sum(isinstance(r, ValueError) for r in results) == 1
    assert len(manager.quarantines()) == 1


async def test_firewall_uses_exact_rule_and_records_permission_failure(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from security_agent import incident_response as module
    manager = IncidentManager(tmp_path / 'ir')
    monkeypatch.setattr(module.platform, 'system', lambda: 'Windows')
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs.get('shell') is not True
        return SimpleNamespace(returncode=1, stdout='Access denied', stderr='')

    monkeypatch.setattr(module.subprocess, 'run', run)
    pending = await manager.submit_command('block_indicator', '192.0.2.1')
    assert commands == []
    denied = await manager.resolve_approval(pending['approval']['approval_id'], 'approve')
    assert denied['action']['status'] == 'failed'
    assert 'Access denied' in denied['action']['error']
    assert 'remoteip=192.0.2.1' in commands[0]
    assert 'name=SecMind-' + pending['action']['action_id'] in commands[0]
    assert all('delete' not in command for command in commands)


async def test_unblock_rejects_pending_and_already_completed_request(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from security_agent import incident_response as module

    monkeypatch.setattr(module.platform, 'system', lambda: 'Windows')
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='Ok.', stderr='')

    monkeypatch.setattr(module.subprocess, 'run', run)
    manager = IncidentManager(tmp_path / 'ir')
    block = await manager.submit_command('block_indicator', '192.0.2.2')
    await manager.resolve_approval(block['approval']['approval_id'], 'approve')
    block_id = block['action']['action_id']
    unblock = await manager.submit_command('unblock_indicator', block_id)
    with pytest.raises(ValueError, match='待处理'):
        await manager.submit_command('unblock_indicator', block_id)
    await manager.resolve_approval(unblock['approval']['approval_id'], 'approve')
    with pytest.raises(ValueError, match='已经撤销'):
        await manager.submit_command('unblock_indicator', block_id)
    assert len(calls) == 2


async def test_security_log_failure_is_preserved(tmp_path, monkeypatch):
    from security_agent import incident_response as module
    manager = IncidentManager(tmp_path / 'ir')
    monkeypatch.setattr(module, 'collect_security_events', lambda: {'records': [], 'errors': ['Access denied'], 'complete': False})
    result = await manager.submit_command('collect_security_events')
    assert result['action']['status'] == 'failed'
    assert manager.snapshot()['inventory']['security_events']['complete'] is False


async def test_pending_approvals_are_returned_before_resolved_history(tmp_path):
    manager = IncidentManager(tmp_path / 'ir')
    first = await manager.submit_command('block_indicator', '192.0.2.10')
    for target in ('192.0.2.11', '192.0.2.12'):
        resolved = await manager.submit_command('block_indicator', target)
        await manager.resolve_approval(resolved['approval']['approval_id'], 'deny')
    listed = manager.approvals(limit=2)
    assert listed[0]['approval_id'] == first['approval']['approval_id']
    assert listed[0]['status'] == 'pending'


def test_incident_history_and_old_firewall_actions_remain_available(settings):
    app = create_app(settings)
    manager = app.state.incident_manager
    manager._actions = [
        {'action_id': f'block-{i}', 'command': 'block_indicator', 'target': f'192.0.2.{i % 250 + 1}',
         'status': 'completed', 'label': '阻断'} for i in range(130)
    ]
    manager._actions.append({'action_id': 'unblock-1', 'command': 'unblock_indicator',
                             'target': 'block-1', 'status': 'completed', 'label': '撤销阻断'})
    manager._approvals = {f'approval-{i}': {'approval_id': f'approval-{i}', 'status': 'pending'}
                          for i in range(205)}
    with sqlite3.connect(manager.store.path) as db:
        db.executemany('INSERT INTO receipts(kind,value) VALUES (?, ?)',
                       [('incident', json.dumps({'sequence': i, 'event_type': 'audit'})) for i in range(520)])
    with TestClient(app) as client:
        actions = client.get('/api/v1/incident/actions', params={'limit': 20, 'offset': 120}).json()
        logs = client.get('/api/v1/incident/logs', params={'limit': 20, 'offset': 500}).json()
        pending = client.get('/api/v1/incident/pending-approvals').json()['approvals']
        eligible = client.get('/api/v1/incident/eligible-unblocks').json()['actions']
    assert actions['total'] == 131 and actions['actions'][-1]['action_id'] == 'block-0'
    assert logs['total'] == 520 and logs['logs'][-1]['sequence'] == 0
    assert len(pending) == 205
    assert any(action['action_id'] == 'block-0' for action in eligible)
    assert all(action['action_id'] != 'block-1' for action in eligible)


@pytest.mark.parametrize('stored_sequences', [[], [1, 3]])
def test_incident_snapshot_logs_are_restored_without_duplicates(tmp_path, stored_sequences):
    root = tmp_path / 'ir'
    manager = IncidentManager(root)
    history = [{'sequence': sequence, 'event_type': 'legacy.audit', 'message': str(sequence)}
               for sequence in (1, 2, 3)]
    manager.store.put('incident', {'logs': history, 'sequence': 3})
    for sequence in stored_sequences:
        manager.store.append('incident', history[sequence - 1])

    restored = IncidentManager(root)
    assert [entry['sequence'] for entry in restored.logs()] == [3, 2, 1]
    assert restored.store.receipt_count('incident') == 3
    restarted = IncidentManager(root)
    assert [entry['sequence'] for entry in restarted.logs()] == [3, 2, 1]
    assert restarted.store.receipt_count('incident') == 3


async def test_read_only_incident_commands_return_their_collected_data(tmp_path, monkeypatch):
    from security_agent import incident_response as module

    manager = IncidentManager(tmp_path / 'ir')
    sample = {
        'collected_at': '2026-10-04T00:00:00Z', 'hostname': 'local-fixture',
        'platform': 'test', 'processes': [{'pid': 7, 'name': 'fixture'}],
        'listeners': [{'address': '127.0.0.1', 'port': 8003}],
        'interfaces': [{'name': 'loopback', 'address': '127.0.0.1'}],
        'findings': [], 'errors': [], 'complete': True,
    }
    monkeypatch.setattr(module, 'collect_host', lambda: dict(sample))
    assets = await manager.submit_command('scan_assets')
    assert assets['action']['result']['listeners'] == sample['listeners']
    processes = await manager.submit_command('inspect_processes')
    assert processes['action']['result']['processes'] == sample['processes']
    baseline = await manager.submit_command('refresh_baseline')
    assert baseline['action']['status'] == 'completed'
    indicators = await manager.submit_command('collect_indicators')
    assert indicators['action']['result']['baseline_at'] == sample['collected_at']
    assert indicators['action']['result']['new_listeners'] == []


async def test_real_mcp_stdio_discovery_execution_schema_and_scope(tmp_path):
    runtime = MCPRuntime(MCPCatalog(storage_path=tmp_path / 'catalog.json'), tmp_path,
                         [tmp_path / 'uploads'], LedgerStore('sqlite:///' + str(tmp_path / 'ledger.db')))
    probe = await runtime.probe('secmind-local')
    assert probe['status'] == 'connected', probe
    assert {tool['name'] for tool in probe['tools']} == {'hash_file', 'inspect_python', 'audit_python', 'decode_base64'}
    result = await runtime.invoke('secmind-local', 'decode_base64', {'text': 'aGVsbG8='}, True)
    assert result['status'] == 'completed', result
    assert json.loads(result['result']['content'][0]['text'])['text'] == 'hello'
    invalid = await runtime.invoke('secmind-local', 'decode_base64', {'bad': 1}, True)
    assert invalid['status'] == 'failed'
    outside = tmp_path / 'outside.txt'
    outside.write_text('private')
    denied = await runtime.invoke('secmind-local', 'hash_file', {'path': str(outside)}, True)
    assert denied['status'] == 'failed'
    allowed = tmp_path / 'uploads' / 'sample.py'
    allowed.parent.mkdir()
    allowed.write_text('def hello():\n    return 1\n')
    hashed = await runtime.invoke('secmind-local', 'hash_file', {'path': str(allowed)}, True)
    assert json.loads(hashed['result']['content'][0]['text'])['sha256'] == hashlib.sha256(allowed.read_bytes()).hexdigest()
    parsed = await runtime.invoke('secmind-local', 'inspect_python', {'path': str(allowed)}, True)
    assert json.loads(parsed['result']['content'][0]['text'])['functions'] == [{'name': 'hello', 'line': 1}]
    allowed.write_text('import subprocess\ndef run(value):\n    subprocess.run(value, shell=True)\n')
    audited = await runtime.invoke('secmind-local', 'audit_python', {'path': str(allowed)}, True)
    assert audited['status'] == 'completed', audited
    assert any(f['test_id'] == 'B602' for f in json.loads(audited['result']['content'][0]['text'])['findings'])
    assert len(runtime.store.recent('mcp')) == 6


@pytest.mark.parametrize('cancel_during_call', [False, True])
async def test_mcp_cancellation_persists_terminal_receipt(tmp_path, monkeypatch, cancel_during_call):
    ledger = LedgerStore('sqlite:///' + str(tmp_path / 'ledger.db'))
    ledger.save_state(AgentState(run_id='cancelled-call', task=TaskRequest(objective='MCP cancellation')))
    runtime = MCPRuntime(MCPCatalog(storage_path=tmp_path / 'catalog.json'), tmp_path,
                         [tmp_path / 'uploads'], ledger)
    entered = asyncio.Event()
    before_entered = asyncio.Event()
    release = asyncio.Event()

    class Session:
        async def call_tool(self, *_args):
            entered.set()
            await release.wait()

    @asynccontextmanager
    async def fake_session(_server):
        yield Session()

    async def fake_tools(_session):
        return [{'name': 'decode_base64', 'description': 'test',
                 'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}},
                                 'required': ['text']}}]

    monkeypatch.setattr(runtime, 'session', fake_session)
    monkeypatch.setattr(runtime, '_tools', fake_tools)

    async def cancel_before_tool():
        before_entered.set()
        await asyncio.sleep(3600)

    before_call = cancel_before_tool if not cancel_during_call else None
    task = asyncio.create_task(runtime.invoke(
        'secmind-local', 'decode_base64', {'text': 'aGVsbG8='}, True,
        run_id='cancelled-call', before_call=before_call,
    ))
    if cancel_during_call:
        await entered.wait()
    else:
        # The callback is deliberately cancellable and runs after schema and
        # connection checks, before the request is sent to the tool.
        await before_entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    receipt = runtime.store.recent('mcp')[0]
    assert receipt['status'] == ('interrupted' if cancel_during_call else 'cancelled')
    assert receipt['completed_at']
    assert runtime.store.get('call:' + receipt['call_id']) == receipt
    assert entered.is_set() == cancel_during_call
    events = ledger.events('cancelled-call')
    assert events[-1].event_type == 'mcp.call.' + receipt['status']
    assert events[-1].payload['call_id'] == receipt['call_id']
    assert ledger.verify('cancelled-call')


@pytest.mark.parametrize('recovery_saved', [False, True])
def test_mcp_restart_recovery_records_one_terminal_ledger_event(tmp_path, recovery_saved):
    ledger = LedgerStore('sqlite:///' + str(tmp_path / 'ledger.db'))
    ledger.save_state(AgentState(run_id='crashed-call', task=TaskRequest(objective='MCP recovery')))
    catalog = MCPCatalog(storage_path=tmp_path / 'catalog.json')
    runtime = MCPRuntime(catalog, tmp_path, [tmp_path / 'uploads'], ledger)
    receipt = {
        'call_id': 'a93df8c4-80ab-45ba-82ed-94d3b224212c',
        'run_id': 'crashed-call',
        'status': 'running',
        'tool': 'decode_base64',
    }
    if recovery_saved:
        # Simulate a crash after persisting the recovered status but before
        # the separate Ledger transaction committed.
        receipt.update(status='interrupted', recovered_at_startup=True,
                       completed_at='2026-10-03T00:00:00+00:00')
    runtime.store.put('call:' + receipt['call_id'], receipt)

    MCPRuntime(catalog, tmp_path, [tmp_path / 'uploads'], ledger)
    recovered = runtime.store.get('call:' + receipt['call_id'])
    assert recovered['status'] == 'interrupted'
    assert recovered['completed_at']
    assert [event.event_type for event in ledger.events('crashed-call')] == ['mcp.call.interrupted']

    MCPRuntime(catalog, tmp_path, [tmp_path / 'uploads'], ledger)
    assert len(ledger.events('crashed-call')) == 1
    assert ledger.verify('crashed-call')


async def test_mcp_request_registered_before_call_is_not_replayed_after_restart(tmp_path):
    ledger = LedgerStore('sqlite:///' + str(tmp_path / 'ledger.db'))
    catalog = MCPCatalog(storage_path=tmp_path / 'catalog.json')
    runtime = MCPRuntime(catalog, tmp_path, [tmp_path / 'uploads'], ledger)
    receipt = {
        'call_id': 'a93df8c4-80ab-45ba-82ed-94d3b224212c',
        'server_id': 'secmind-local', 'tool': 'decode_base64',
        'arguments': {'text': 'aGVsbG8='}, 'run_id': None,
        'status': 'running', 'idempotency_key': 'anonymous::crash-before-call-001',
    }
    claimed, _ = runtime.store.claim_mcp_request(
        receipt['idempotency_key'], receipt['call_id'], receipt,
    )
    assert claimed

    restarted = MCPRuntime(catalog, tmp_path, [tmp_path / 'uploads'], ledger)
    replay = await restarted.invoke(
        'secmind-local', 'decode_base64', {'text': 'aGVsbG8='},
        approved=True, request_id='crash-before-call-001',
    )
    assert replay['status'] == 'interrupted'
    assert replay['recovered_at_startup'] is True
    assert restarted.store.get('call:' + receipt['call_id']) == replay
    assert restarted.store.recent('mcp') == [replay]


async def test_partial_evidence_download_is_verified(settings, monkeypatch):
    app = create_app(settings)
    manager = app.state.incident_manager
    original_scan = manager._scan

    async def partial_scan():
        inventory = await original_scan()
        return {**inventory, 'errors': ['fixture: one optional source unavailable']}

    monkeypatch.setattr(manager, '_scan', partial_scan)
    with TestClient(app) as client:
        result = client.post('/api/v1/incident/command', json={'command': 'collect_evidence'})
        assert result.status_code == 200
        action = result.json()['action']
        assert action['status'] == 'partial'
        receipt = action['result']
        path = '/api/v1/incident/evidence/' + receipt['evidence_id']
        download = client.get(path)
        assert download.status_code == 200
        assert hashlib.sha256(download.content).hexdigest() == receipt['sha256']
        evidence = manager.root / 'evidence' / (receipt['evidence_id'] + '.json')
        evidence.write_bytes(b'{}')
        assert client.get(path).status_code == 409


def test_evidence_api_upload_and_origin_protection(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        blocked = client.post('/api/v1/incident/command', json={'command': 'scan_assets'}, headers={'origin': 'https://other.example'})
        assert blocked.status_code == 403
        upload = client.post('/api/v1/incident/samples', files={'file': ('safe.txt', b'test')}).json()
        pending = client.post('/api/v1/incident/command', json={'command': 'isolate_sample', 'target': upload['path']}).json()
        assert pending['action']['status'] == 'awaiting_approval'
        result = client.post('/api/v1/incident/command', json={'command': 'collect_evidence'}).json()
        assert result['action']['status'] == 'completed'
        receipt = result['action']['result']
        download = client.get('/api/v1/incident/evidence/' + receipt['evidence_id'])
        assert hashlib.sha256(download.content).hexdigest() == receipt['sha256']
        assert download.headers['X-Evidence-SHA256'] == receipt['sha256']
        assert download.json()['scope'] == 'local_host'
        evidence_path = app.state.incident_manager.root / 'evidence' / (receipt['evidence_id'] + '.json')
        evidence_path.write_bytes(b'{"tampered":true}')
        assert client.get('/api/v1/incident/evidence/' + receipt['evidence_id']).status_code == 409
        dashboard = client.get('/api/v1/dashboard').json()
        assert dashboard['host']['inventory']['processes']


def test_incident_sample_upload_rejects_invalid_filenames_without_leaving_directories(settings):
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        for filename in (b'bad\x00name.txt', b'/', b'CON.txt'):
            body = (b'--test\r\nContent-Disposition: form-data; name="file"; filename="'
                    + filename + b'"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--test--\r\n')
            response = client.post('/api/v1/incident/samples', content=body,
                                   headers={'Content-Type': 'multipart/form-data; boundary=test'})
            assert response.status_code == 422
    assert list((app.state.incident_manager.root / 'samples').iterdir()) == []


def test_incident_approval_survives_api_restart_and_denial_preserves_sample(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        uploaded = client.post('/api/v1/incident/samples', files={'file': ('fixture.txt', b'keep me')})
        assert uploaded.status_code == 200
        sample = uploaded.json()['path']
        pending = client.post('/api/v1/incident/command', json={
            'command': 'isolate_sample', 'target': sample, 'reason': 'isolated approval regression',
        })
        assert pending.status_code == 200
        assert pending.json()['action']['status'] == 'awaiting_approval'
        approval_id = pending.json()['approval']['approval_id']
    restarted = create_app(settings)
    with TestClient(restarted) as client:
        listed = client.get('/api/v1/incident/pending-approvals').json()['approvals']
        assert [item['approval_id'] for item in listed] == [approval_id]
        denied = client.post(f'/api/v1/incident/approvals/{approval_id}', json={'decision': 'deny'})
        assert denied.status_code == 200
        assert denied.json()['action']['status'] == 'denied'
        assert client.get('/api/v1/incident/pending-approvals').json()['approvals'] == []
    assert open(sample, 'rb').read() == b'keep me'


async def test_prompt_edits_reach_actual_request_with_version_receipt(settings):
    prompts = RuntimePrompts(settings.run_root.parent)
    old = prompts.get('report', include_content=True)
    saved = prompts.update('report', 'UNIQUE_RUNTIME_INSTRUCTION', old['checksum'])
    with pytest.raises(ValueError, match='版本已变更'):
        prompts.update('report', 'stale edit', old['checksum'])
    events, requests = [], []

    class Output(BaseModel):
        answer: str

    def handler(request):
        requests.append(json.loads(request.content))
        chunk = json.dumps({'choices': [{'delta': {'content': '{"answer":"ok"}'}, 'finish_reason': 'stop'}]})
        return httpx.Response(200, text='data: ' + chunk + '\n\ndata: [DONE]\n\n', headers={'content-type': 'text/event-stream'})

    async def observe(kind, payload):
        events.append((kind, payload))

    settings.demo_mode = False
    settings.model_api_key = 'test'
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gateway = ModelGateway(settings, client)
        output, meta = await gateway.structured(role='worker', stage='report', system_prompt='existing constraints',
            user_prompt='evidence', output_model=Output, prompt_version='old', stream_observer=observe)
    assert output.answer == 'ok'
    assert 'UNIQUE_RUNTIME_INSTRUCTION' in requests[0]['messages'][0]['content']
    assert 'existing constraints' in requests[0]['messages'][0]['content']
    assert meta.prompt_version == saved['version']
    assert any(kind == 'llm.prompt.selected' and payload['checksum'] == saved['checksum'] for kind, payload in events)
