import json
import sqlite3
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import update

from security_agent.api import _run_usage, create_app
from security_agent.external_usage import ExternalUsageCollector
from security_agent.ledger import EventRow
from security_agent.pi_usage_backfill import backfill_pi_usage
from security_agent.schemas import AgentState, RunStatus, TaskRequest


def worker_receipts(path, rows):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS usage_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, receipt_id TEXT UNIQUE, payload_json TEXT)')
        for trace, state, usage, timestamp in rows:
            conn.execute('INSERT INTO usage_events(receipt_id, payload_json) VALUES (?, ?)',
                (trace + ':' + state, json.dumps({'trace_id': trace, 'status': state, 'model': 'worker',
                 'project_id': 'proj_1', 'usage': usage, 'occurred_at': timestamp, 'api_key': 'must-not-copy'})))


def secmind_database(path):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE outbox_events (run_id TEXT, event_type TEXT, created_at TEXT, payload_json TEXT)')
        conn.execute('CREATE TABLE investigation_objects (run_id TEXT, object_type TEXT, payload_json TEXT)')
        base = {'model_id': 'engine', 'succeeded': True, 'usage': {'input_tokens': 999999}}
        for trace, extra in [('actual', {'provider_reported_usage': {'provider_requests': 1, 'input_tokens': 7, 'output_tokens': 3}, 'unknown_usage': False}),
                             ('estimated', {'provider_reported_usage': {'provider_requests': 0, 'input_tokens': 0, 'output_tokens': 0}, 'unknown_usage': True}),
                             ('legacy', {}), ('legacy-known', {})]:
            conn.execute('INSERT INTO outbox_events VALUES (?, ?, ?, ?)', ('remote_1', 'model.attempt_recorded',
                datetime.now(UTC).isoformat(), json.dumps({**base, 'provider_request_id': trace, **extra})))
        conn.execute('INSERT INTO investigation_objects VALUES (?, ?, ?)', ('remote_1', 'model.raw_response_receipt.v1',
            json.dumps({'schema_version': '1.1', 'provider_request_id': 'legacy-known', 'unknown_usage_attempts': 0,
                        'provider_reported_usage': {'provider_requests': 1, 'input_tokens': 20, 'output_tokens': 2}})))


def secmind_partial_database(path):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE outbox_events (run_id TEXT, event_type TEXT, created_at TEXT, payload_json TEXT)')
        conn.execute('CREATE TABLE investigation_objects (run_id TEXT, object_type TEXT, payload_json TEXT)')
        conn.execute('INSERT INTO outbox_events VALUES (?, ?, ?, ?)', (
            'remote_partial', 'model.attempt_recorded', datetime.now(UTC).isoformat(), json.dumps({
                'provider_request_id': 'partial', 'model_id': 'engine', 'succeeded': True,
                # SecMind marks the attempt unknown because another usage
                # field was absent, while these provider fields are confirmed.
                'provider_reported_usage': {
                    'provider_requests': 0, 'input_tokens': 7, 'output_tokens': 3,
                },
                'unknown_usage': True,
            })))


def test_external_partial_provider_usage_is_counted_without_clearing_unknown_status(settings):
    settings.prepare_directories()
    settings.secmind_usage_database = settings.run_root.parent / 'partial-engine.db'
    secmind_partial_database(settings.secmind_usage_database)
    app = create_app(settings)
    with TestClient(app) as client:
        result = client.get('/api/v1/model-usage').json()
        assert result['total_tokens'] == 10
        assert result['usage_receipt_count'] == 1
        assert result['partial_usage_count'] == 1
        assert result['missing_usage_count'] == 0
        source = next(row for row in result['usage_by_source'] if row['source'] == 'secmind')
        assert source['total_tokens'] == 10
        assert source['partial_usage_count'] == 1
        assert source['missing_usage_count'] == 0
        event = app.state.service.ledger.events_by_type('external.usage.completed', limit=None)[0]
        assert event.payload['usage_provenance'] == 'provider_reported_partial'
        assert event.payload['usage_partial'] is True


def test_partial_usage_reimport_upgrades_old_empty_receipt_without_changing_identity(settings):
    settings.prepare_directories()
    settings.secmind_usage_database = settings.run_root.parent / 'partial-upgrade.db'
    secmind_partial_database(settings.secmind_usage_database)
    with sqlite3.connect(settings.secmind_usage_database) as conn:
        original = json.loads(conn.execute('SELECT payload_json FROM outbox_events').fetchone()[0])
        original['provider_reported_usage']['input_tokens'] = 0
        original['provider_reported_usage']['output_tokens'] = 0
        conn.execute('UPDATE outbox_events SET payload_json = ?', (json.dumps(original),))
    app = create_app(settings)
    with TestClient(app) as client:
        first = client.get('/api/v1/model-usage').json()
        assert first['total_tokens'] == 0
        assert first['missing_usage_count'] == 1
        with sqlite3.connect(settings.secmind_usage_database) as conn:
            original['provider_reported_usage']['input_tokens'] = 7
            original['provider_reported_usage']['output_tokens'] = 3
            conn.execute('UPDATE outbox_events SET payload_json = ?', (json.dumps(original),))
        ledger = app.state.service.ledger
        assert ExternalUsageCollector(settings, ledger).sync()['secmind']['status'] == 'synced'
        upgraded = client.get('/api/v1/model-usage').json()
        assert upgraded['total_tokens'] == 10
        assert upgraded['model_call_count'] == 1
        assert upgraded['partial_usage_count'] == 1
        assert upgraded['missing_usage_count'] == 0
        assert len(ledger.events_by_type('external.usage.completed', limit=None)) == 2
        assert ExternalUsageCollector(settings, ledger).sync()['secmind']['status'] == 'synced'
        assert client.get('/api/v1/model-usage').json()['total_tokens'] == 10


def test_external_receipts_replay_unknown_history_and_chart_conservation(settings):
    settings.prepare_directories()
    settings.secmind_usage_database = settings.run_root.parent / 'engine.db'
    secmind_database(settings.secmind_usage_database)
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    now = datetime.now(UTC).isoformat()
    worker_receipts(settings.run_root.parent / 'worker-usage.db', [
        ('ok', 'started', {}, old), ('ok', 'completed', {'prompt_tokens': 100, 'completion_tokens': 5, 'cache_read_tokens': 40}, old),
        ('failure', 'started', {}, now), ('failure', 'failed', {}, now),
        ('crashed', 'started', {}, now),
        ('zero', 'completed', {'prompt_tokens': 0, 'completion_tokens': 0}, now)])
    app = create_app(settings)
    app.state.service.ledger.save_state(AgentState(
        run_id='linked-platform-run', task=TaskRequest(objective='inspect linked usage'),
        external_execution={'project_id': 'proj_1'}))
    with TestClient(app) as client:
        first = client.get('/api/v1/model-usage').json()
        assert first['total_tokens'] == 137
        assert first['model_call_count'] == 8
        assert first['missing_usage_count'] == 4
        assert first['incomplete_call_count'] == 1
        assert first['usage_receipt_count'] == 4
        assert first['series']['daily'][-1]['tokens'] == 32  # Historical import is not today's spend.
        assert sum(p['tokens'] for p in first['series']['daily']) == 137
        assert sum(s['total_tokens'] for s in first['usage_by_source']) == 137
        assert sum(m['total_tokens'] for m in first['models']) == 137
        assert first['quota_mode'] == 'warning_only'
        ledger = app.state.service.ledger
        before = len(ledger.events_by_type('external.usage.completed', limit=None))
        # Fresh collector simulates a restart; repeats must not inflate the ledger.
        ExternalUsageCollector(settings, ledger).sync()
        second = client.get('/api/v1/model-usage').json()
        assert second['total_tokens'] == first['total_tokens']
        assert len(ledger.events_by_type('external.usage.completed', limit=None)) == before
        events = ledger.events_by_type('external.usage.completed', limit=None)
        assert all(ledger.verify(e.run_id) for e in events)
        assert 'must-not-copy' not in json.dumps([e.payload for e in events])
        linked = _run_usage(ledger, 'platform-run', external_execution={'project_id': 'proj_1'})
        assert linked['total_tokens'] == 105 and linked['model_call_count'] == 4
        listed = next(item for item in client.get('/api/v1/runs').json()['runs']
                      if item['run_id'] == 'linked-platform-run')
        detailed = client.get('/api/v1/runs/linked-platform-run').json()
        assert listed['usage']['total_tokens'] == detailed['usage']['total_tokens'] == 105
        linked = _run_usage(ledger, 'platform-run', external_execution={'remote_run_id': 'remote_1'})
        assert linked['total_tokens'] == 32


def test_external_source_outage_preserves_known_usage(settings):
    settings.prepare_directories()
    path = settings.run_root.parent / 'worker-usage.db'
    worker_receipts(path, [('one', 'completed', {'total_tokens': 8}, datetime.now(UTC).isoformat())])
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get('/api/v1/model-usage').json()['total_tokens'] == 8
        path.write_bytes(b'invalid sqlite')
        data = client.get('/api/v1/model-usage').json()
        assert data['total_tokens'] == 8
        source = next(s for s in data['usage_by_source'] if s['source'] == 'security_runtime_worker')
        assert source['status'] == 'error'


def test_reused_worker_project_id_does_not_copy_usage_into_older_run(settings):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    old = datetime.now(UTC) - timedelta(days=1)
    current = datetime.now(UTC)
    worker_receipts(journal, [('older', 'completed', {'total_tokens': 7}, old.isoformat()),
                              ('newer', 'completed', {'total_tokens': 11}, current.isoformat())])
    app = create_app(settings)
    ledger = app.state.service.ledger
    for run_id, time in [('older-run', old), ('newer-run', current)]:
        ledger.save_state(AgentState(run_id=run_id, task=TaskRequest(objective='inspect usage'),
                                     external_execution={'project_id': 'proj_1'}))
        event = ledger.append(run_id, 'report.generated', {}, actor='test')
        with ledger.engine.begin() as conn:
            conn.execute(update(EventRow).where(EventRow.event_id == event.event_id).values(timestamp=time))
    # A later report refresh must not widen the old project's execution period.
    ledger.append('older-run', 'report.refreshed', {}, actor='test')
    with TestClient(app) as client:
        listed = {item['run_id']: item['usage']['total_tokens']
                  for item in client.get('/api/v1/runs').json()['runs']}
        assert listed['older-run'] == 7
        assert listed['newer-run'] == 11
        for run_id in ('older-run', 'newer-run'):
            assert client.get(f'/api/v1/runs/{run_id}').json()['usage']['total_tokens'] == listed[run_id]


def test_terminal_run_with_stale_submitted_project_does_not_claim_later_worker_usage(settings):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    old = datetime.now(UTC) - timedelta(days=1)
    current = datetime.now(UTC)
    worker_receipts(journal, [('older', 'completed', {'total_tokens': 7}, old.isoformat()),
                              ('newer', 'completed', {'total_tokens': 11}, current.isoformat())])
    app = create_app(settings)
    ledger = app.state.service.ledger
    ledger.save_state(AgentState(run_id='old-run', task=TaskRequest(objective='inspect usage'),
                                 status=RunStatus.PARTIAL,
                                 external_execution={'project_id': 'proj_1', 'status': 'submitted'}))
    event = ledger.append('old-run', 'report.generated', {}, actor='test')
    with ledger.engine.begin() as conn:
        conn.execute(update(EventRow).where(EventRow.event_id == event.event_id).values(timestamp=old))
    with TestClient(app) as client:
        listed = client.get('/api/v1/runs').json()['runs'][0]['usage']['total_tokens']
        detail = client.get('/api/v1/runs/old-run').json()['usage']['total_tokens']
    assert listed == detail == 7


def test_pi_session_backfill_adds_tokens_without_inflating_execution_calls(settings, tmp_path):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    begin = datetime.now(UTC) - timedelta(minutes=2)
    end = begin + timedelta(minutes=1)
    worker_receipts(journal, [('old', 'started', {}, begin.isoformat()),
                              ('old', 'completed', {}, end.isoformat())])
    with sqlite3.connect(journal) as conn:
        for state in ('started', 'completed'):
            conn.execute("UPDATE usage_events SET payload_json=json_set(payload_json, '$.worker', 'pi_default', "
                         "'$.call_unit', 'cli_execution') WHERE receipt_id=?", ('old:' + state,))
    sessions = tmp_path / 'pi_default' / 'sessions'
    sessions.mkdir(parents=True)
    entry = {'type': 'message', 'id': 'response-1', 'timestamp': (begin + timedelta(seconds=20)).isoformat(),
             'message': {'role': 'assistant', 'model': 'pi-model',
                         'content': [{'type': 'text', 'text': 'private model text'}],
                         'usage': {'input': 5, 'output': 2, 'cacheRead': 20, 'cacheWrite': 3}}}
    second = {**entry, 'id': 'response-2', 'timestamp': (begin + timedelta(seconds=25)).isoformat()}
    (sessions / 'one.jsonl').write_text(json.dumps(entry) + '\n' + json.dumps(second) + '\n',
                                       encoding='utf-8')
    first_backfill = backfill_pi_usage(journal, tmp_path)
    assert first_backfill['inserted_tokens'] == 60
    assert first_backfill['linked_tokens'] == 60
    assert backfill_pi_usage(journal, tmp_path)['inserted_tokens'] == 0
    with sqlite3.connect(journal) as conn:
        bodies = [row[0] for row in conn.execute('SELECT payload_json FROM usage_events')]
    assert all('private model text' not in body for body in bodies)
    app = create_app(settings)
    with TestClient(app) as client:
        result = client.get('/api/v1/model-usage').json()
        assert result['total_tokens'] == 60
        assert result['model_call_count'] == 1
        assert result['backfilled_response_count'] == 2
        assert result['usage_by_source'][-1]['call_count'] == 1
        assert sum(item['tokens'] for item in result['series']['daily']) == 60
        assert sum(item['calls'] for item in result['series']['daily']) == 1
        linked = _run_usage(app.state.service.ledger, 'platform-run',
                            external_execution={'project_id': 'proj_1'})
        assert linked['total_tokens'] == 60
        assert linked['model_call_count'] == 1


def test_claude_session_backfill_adds_tokens_without_inflating_cli_calls(settings):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    timestamp = datetime.now(UTC).isoformat()
    worker_receipts(journal, [('claude-response', 'completed', {'total_tokens': 19}, timestamp)])
    with sqlite3.connect(journal) as conn:
        conn.execute("UPDATE usage_events SET payload_json=json_set(payload_json, '$.worker', 'claudecode_shared_model', "
                     "'$.call_unit', 'claude_session_response_backfill')")

    app = create_app(settings)
    with TestClient(app) as client:
        result = client.get('/api/v1/model-usage').json()
    worker = next(row for row in result['usage_by_source'] if row['source'] == 'security_runtime_worker')
    assert result['total_tokens'] == 19
    assert result['model_call_count'] == result['completed_call_count'] == 0
    assert result['backfilled_response_count'] == 1
    assert result['missing_usage_count'] == 0
    assert worker['call_count'] == 0
    assert worker['backfilled_response_count'] == 1


def test_pi_backfill_recovers_adjacent_dispatcher_responses_only(settings, tmp_path):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    begin = datetime.now(UTC) - timedelta(minutes=2)
    end = begin + timedelta(seconds=20)
    worker_receipts(journal, [('old', 'started', {}, begin.isoformat()),
                              ('old', 'completed', {}, end.isoformat())])
    with sqlite3.connect(journal) as conn:
        for state in ('started', 'completed'):
            conn.execute("UPDATE usage_events SET payload_json=json_set(payload_json, '$.worker', 'pi_default', "
                         "'$.call_unit', 'cli_execution') WHERE receipt_id=?", ('old:' + state,))
    sessions = tmp_path / 'pi_default' / 'sessions'
    sessions.mkdir(parents=True)
    response = lambda ident, when: {'type': 'message', 'id': ident, 'timestamp': when.isoformat(),
        'message': {'role': 'assistant', 'model': 'pi-model',
                    'usage': {'input': 5, 'output': 2, 'cacheRead': 20, 'cacheWrite': 3}}}
    for name, project, offset in [('linked', 'proj_1', 25), ('wrong', 'proj_2', 25),
                                   ('distant', 'proj_1', 200)]:
        started = begin + timedelta(seconds=offset)
        rows = [{'type': 'session', 'timestamp': started.isoformat(),
                 'cwd': str(tmp_path / 'dispatcher-workspaces' / project)},
                response(name, started + timedelta(seconds=1))]
        (sessions / f'{name}.jsonl').write_text('\n'.join(map(json.dumps, rows)) + '\n', encoding='utf-8')
    result = backfill_pi_usage(journal, tmp_path)
    assert result['inserted_responses'] == 1
    assert result['inserted_tokens'] == 30
    assert backfill_pi_usage(journal, tmp_path)['inserted_tokens'] == 0
    with sqlite3.connect(journal) as conn:
        recovered = [json.loads(body) for (body,) in conn.execute(
            "SELECT payload_json FROM usage_events WHERE receipt_id LIKE 'pi-session-backfill:%'")]
    assert recovered[0]['project_id'] == 'proj_1'


def test_pi_backfill_links_overlapping_receipts_by_session_workspace(settings, tmp_path):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    begin = datetime.now(UTC) - timedelta(minutes=2)
    end = begin + timedelta(minutes=1)
    worker_receipts(journal, [(trace, state, {}, timestamp)
                              for trace in ('first', 'second')
                              for state, timestamp in (('started', begin.isoformat()),
                                                       ('completed', end.isoformat()))])
    with sqlite3.connect(journal) as conn:
        conn.execute("UPDATE usage_events SET payload_json=json_set(payload_json, '$.project_id', 'proj_2') "
                     "WHERE receipt_id LIKE 'second:%'")
        conn.execute("UPDATE usage_events SET payload_json=json_set(payload_json, '$.worker', 'pi_default', "
                     "'$.call_unit', 'cli_execution')")
    sessions = tmp_path / 'pi_default' / 'sessions'
    sessions.mkdir(parents=True)
    rows = [{'type': 'session', 'timestamp': begin.isoformat(),
             'cwd': str(tmp_path / 'dispatcher-workspaces' / 'proj_2')},
            {'type': 'message', 'id': 'response', 'timestamp': (begin + timedelta(seconds=20)).isoformat(),
             'message': {'role': 'assistant', 'model': 'pi-model',
                         'usage': {'input': 5, 'output': 2, 'cacheRead': 20, 'cacheWrite': 3}}}]
    session = sessions / 'overlap.jsonl'
    session.write_text(json.dumps(rows[1]) + '\n', encoding='utf-8')
    first = backfill_pi_usage(journal, tmp_path)
    assert first['inserted_tokens'] == 30 and first['linked_tokens'] == 0
    session.write_text('\n'.join(map(json.dumps, rows)) + '\n', encoding='utf-8')
    result = backfill_pi_usage(journal, tmp_path)
    assert result['inserted_tokens'] == 0 and result['linked_tokens'] == 30
    with sqlite3.connect(journal) as conn:
        receipt = json.loads(conn.execute(
            "SELECT payload_json FROM usage_events WHERE receipt_id LIKE 'pi-session-backfill:%'").fetchone()[0])
    assert receipt['project_id'] == 'proj_2'
    assert backfill_pi_usage(journal, tmp_path)['inserted_tokens'] == 0


def test_external_collector_drains_multiple_receipt_pages_in_one_sync(settings):
    settings.prepare_directories()
    journal = settings.run_root.parent / 'worker-usage.db'
    with sqlite3.connect(journal) as conn:
        conn.execute('CREATE TABLE usage_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, '
                     'receipt_id TEXT UNIQUE, payload_json TEXT)')
        for number in range(2001):
            body = {'trace_id': str(number), 'status': 'completed', 'model': 'worker',
                    'usage': {'total_tokens': 1}, 'occurred_at': datetime.now(UTC).isoformat()}
            conn.execute('INSERT INTO usage_events(receipt_id,payload_json) VALUES (?,?)',
                         (str(number) + ':completed', json.dumps(body)))
    app = create_app(settings)
    with TestClient(app) as client:
        result = client.get('/api/v1/model-usage').json()
        assert result['total_tokens'] == 2001
        assert result['model_call_count'] == 2001
        assert result['usage_by_source'][-1]['status'] == 'synced'
