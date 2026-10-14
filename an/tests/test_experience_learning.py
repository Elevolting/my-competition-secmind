import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from security_agent.api import create_app
from security_agent.experience import ExperienceDetailRow, ExperienceRow, ExperienceStore
from security_agent.guardrail import Guardrail
from security_agent.ledger import LedgerStore
from security_agent.llm import ModelCallMeta, ModelGateway
from security_agent.orchestrator import SecurityOrchestrator
from security_agent.schemas import (
    AgentReport,
    AgentState,
    AttachmentRef,
    Evidence,
    ExperienceCreateRequest,
    Finding,
    RunStatus,
    Scenario,
    TaskRequest,
    ToolResult,
    ToolStatus,
)
from security_agent.tools import ToolBroker, default_registry


def source_run(ledger, name='source', status='completed'):
    state = AgentState(run_id=name, task=TaskRequest(objective='审计 Python 命令注入 subprocess shell 参数'),
        status=status, scenario=Scenario.CODE_AUDIT,
        evidence=[Evidence(evidence_id='evidence-1', source='bandit', summary='第 3 行 shell=True', artifact_ref='sample.py', sha256='a' * 64)],
        findings=[Finding(rule_id='B602', path='sample.py', title='命令注入', description='外部输入进入 shell=True',
            remediation='参数数组并禁用 shell', evidence_ids=['evidence-1'])],
        observations=[ToolResult(status=ToolStatus.SUCCESS, summary='Bandit 检出 B602')])
    if status == 'completed':
        state.report = AgentReport(run_id=name, status=status, executive_summary='发现命令注入，需改用参数数组', evidence=state.evidence, findings=state.findings)
    else:
        state.last_error = '工具超时，未完成静态审计'
        state.observations = [ToolResult(status=ToolStatus.TIMEOUT, error_code='TIMEOUT', error_message=state.last_error)]
    ledger.save_state(state)
    ledger.append(name, 'tool.completed', {'tool': 'workspace_security_audit', 'status': 'success' if status == 'completed' else 'timeout'})
    return state


def extract(store, ledger, state):
    return store.capture_run(state, ledger.events(state.run_id), chain_valid=ledger.verify(state.run_id))


def note(store, title='命令注入防护', lessons=None):
    return store.create_manual(ExperienceCreateRequest(title=title, summary='外部输入不能拼入 shell 命令',
        conditions=['Python subprocess 调用'], lessons=lessons or ['禁用 shell=True，使用参数数组'], tags=['命令注入', 'Python']))


def test_extract_review_retrieval_delete_and_idempotent_backfill(settings):
    ledger = LedgerStore(settings.database_url)
    store = ExperienceStore(ledger.engine)
    state = source_run(ledger)
    item = extract(store, ledger, state)
    assert item['review_status'] == 'draft'
    assert not item['verified'] and item['confidence'] is None
    assert any('B602' in text and 'evidence-1' in text for text in item['lessons'])
    assert store.search('code_audit', 'Python命令注入') == []
    approved = store.review(item['experience_id'], 'approve', item['version'])
    hits = store.search('code_audit', '检查Python命令注入漏洞')
    assert hits[0]['experience_id'] == item['experience_id']
    assert hits[0]['matched_terms']
    assert store.search('code_audit', '验证椭圆曲线签名') == []
    assert store.search('reverse', 'Python命令注入') == []
    assert store.search('code_audit', 'Python命令注入', exclude_run_id='source') == []
    assert store.get(item['experience_id'])['usage_count'] == 0
    assert store.backfill(ledger)['unchanged'] == 1
    assert store.get(item['experience_id'])['version'] == approved['version']
    store.delete(item['experience_id'])
    assert store.backfill(ledger)['stored'] == 0
    assert ExperienceStore(ledger.engine).list() == []


def test_manual_review_edit_revokes_and_concurrent_stale_edit_fails(settings):
    store = ExperienceStore(settings.database_url)
    item = note(store)
    approved = store.review(item['experience_id'], 'approve', item['version'])
    assert store.search('code_audit', 'subprocess命令注入')
    edited = store.update(item['experience_id'], {'lessons': ['以参数数组传递用户输入']}, approved['version'])
    assert edited['review_status'] == 'draft'
    assert not store.search('code_audit', 'subprocess命令注入')
    with pytest.raises(ValueError, match='版本'):
        store.review(item['experience_id'], 'approve', approved['version'])
    assert len(store.history(item['experience_id'])) == 3


def test_failed_runs_without_report_are_learned_and_invalid_chain_cannot_enable(settings):
    ledger = LedgerStore(settings.database_url)
    store = ExperienceStore(ledger.engine)
    state = source_run(ledger, status='failed')
    item = extract(store, ledger, state)
    assert item['experience_kind'] == 'failure_lesson'
    assert any('TIMEOUT' in text for text in item['lessons'])
    assert store.review(item['experience_id'], 'approve', item['version'])['verified']
    invalid = store.capture_run(state, ledger.events(state.run_id), chain_valid=False)
    assert invalid['review_status'] == 'draft'
    with pytest.raises(ValueError, match='账本'):
        store.review(invalid['experience_id'], 'approve', invalid['version'])


def test_legacy_verified_is_migrated_without_destroying_history(settings):
    store = ExperienceStore(settings.database_url)
    item = note(store)
    with Session(store.engine) as session:
        row = session.get(ExperienceRow, item['experience_id'])
        row.verified, row.confidence, row.usage_count = True, .99, 17
        session.delete(session.get(ExperienceDetailRow, row.experience_id)); session.commit()
    migrated = ExperienceStore(store.engine).get(item['experience_id'])
    assert migrated['review_status'] == 'draft' and migrated['usage_count'] == 0
    assert migrated['legacy_usage_count'] == 17
    assert store.history(item['experience_id'])[0]['snapshot']['confidence'] == .99


async def test_two_tasks_retrieve_inject_to_real_gateway_and_record_outcome(settings):
    ledger = LedgerStore(settings.database_url)
    store = ExperienceStore(ledger.engine)
    settings.prepare_directories()
    (settings.input_root / 'sample.py').write_text(
        "import subprocess\nsubprocess.run(input(), shell=True)\n", encoding='utf-8')
    first_gateway = ModelGateway(settings)
    try:
        first = SecurityOrchestrator(settings, ledger, first_gateway,
            ToolBroker(default_registry(), Guardrail()), experiences=store)
        source = await first.start(TaskRequest(objective='审计 Python 命令注入 subprocess shell 参数',
            attachments=[AttachmentRef(ref='sample.py')]), 'source')
        assert source.status == RunStatus.COMPLETED and source.findings and source.evidence
        item = store.list()[0]
        assert item['source_run_id'] == source.run_id
        assert any('B602' in lesson for lesson in item['lessons'])
    finally:
        await first_gateway.close()
    item = store.review(item['experience_id'], 'approve', item['version'])
    requests = []
    settings.demo_mode = False
    settings.model_api_key = 'test'

    def provider(request):
        body = json.loads(request.content)
        requests.append(body)
        plan = {'steps': [{'step_id': 'audit', 'objective': '检查命令注入', 'agent_role': 'executor',
            'tool_candidates': ['workspace_security_audit'], 'inputs': {'target': '.'}, 'success_criteria': ['核对证据']}],
            'rationale_summary': '参考历史命令注入经验，使用只读审计', 'used_experience_ids': [item['experience_id']]}
        chunk = {'choices': [{'delta': {'content': json.dumps(plan)}, 'finish_reason': 'stop'}]}
        return httpx.Response(200, text='data: ' + json.dumps(chunk) + '\n\ndata: [DONE]\n\n', headers={'content-type': 'text/event-stream'})

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        gateway = ModelGateway(settings, client)
        orchestrator = SecurityOrchestrator(settings, ledger, gateway, ToolBroker(default_registry(), Guardrail()), experiences=store)
        second = AgentState(run_id='next-task', task=TaskRequest(objective='检查Python命令注入 subprocess'), scenario=Scenario.CODE_AUDIT)
        ledger.save_state(second)
        retrieved = await orchestrator._retrieve_context({'agent': second.model_dump(mode='json')})
        assert store.get(item['experience_id'])['usage_count'] == 0
        planned = await orchestrator._plan(retrieved)
        assert item['experience_id'] in requests[0]['messages'][1]['content']
        assert '适用模块' in requests[0]['messages'][1]['content']
        assert 'B602' in requests[0]['messages'][1]['content']
        uses = store.uses(item['experience_id'])
        assert len(uses) == 1 and uses[0]['model_cited'] is True
        assert store.uses_for_run(second.run_id) == uses
        assert uses[0]['version'] == item['version']
        await orchestrator._plan(retrieved)  # Retry does not inflate same-version use count.
        assert store.get(item['experience_id'])['usage_count'] == 1
        completed = AgentState.model_validate(planned['agent'])
        completed.status = RunStatus.COMPLETED
        completed.report = AgentReport(run_id=completed.run_id, status='completed', executive_summary='验证完成')
        await orchestrator._memory_commit({'agent': completed.model_dump(mode='json')})
        assert store.uses(item['experience_id'])[0]['outcome'] == 'completed'
        assert any(e.event_type == 'knowledge.planner_consumed' for e in ledger.events(second.run_id))
        use = store.feedback(item['experience_id'], second.run_id, item['version'], 'helpful', '参数数组建议有帮助')
        assert use['feedback']['verdict'] == 'helpful'
        assert store.search('code_audit', 'Python命令注入')[0]['feedback_counts']['helpful'] == 1


@pytest.mark.parametrize('mode,expected', [('valid', 200), ('invented_ref', 409), ('failure', 502), ('stale', 409)])
def test_model_distillation_saves_only_valid_current_evidence(settings, monkeypatch, mode, expected):
    settings.demo_mode = False
    settings.model_api_key = 'test-only'
    app = create_app(settings)
    store = app.state.experiences
    ledger = app.state.service.ledger
    record = extract(store, ledger, source_run(ledger))
    calls = []

    async def model(self, **kwargs):
        calls.append(kwargs)
        await kwargs['stream_observer']('model.usage', {'usage': {'total_tokens': 12}})
        await kwargs['stream_observer']('llm.stream.delta', {'delta': 'test fragment'})
        if mode == 'failure':
            raise RuntimeError('provider unavailable')
        if mode == 'stale':
            store.update(record['experience_id'], {'summary': '用户在模型返回前手动修正了概要'}, record['version'])
        output = kwargs['output_model'](title='命令注入防护经验', summary='根据静态扫描证据审查 shell 参数',
            conditions=['Python subprocess 外部输入'], lessons=['使用参数数组，禁用 shell'],
            steps=['核对调用位置与输入来源'], limitations=['静态扫描不能证明实际可利用'], tags=['Python'],
            evidence_refs=['invented'] if mode == 'invented_ref' else ['evidence-1'])
        return output, ModelCallMeta(model_id='test-provider', prompt_version='experience-learning-v2',
            response_sha256='b' * 64, duration_ms=1, used_fallback=False, usage={'total_tokens': 12})

    monkeypatch.setattr(ModelGateway, 'structured', model)
    with TestClient(app) as client:
        response = client.post('/api/v1/experiences/' + record['experience_id'] + '/distill')
        assert response.status_code == expected
        saved = store.get(record['experience_id'])
        assert len(calls) == 1 and 'evidence-1' in calls[0]['user_prompt']
        assert not any(e.event_type == 'llm.stream.delta' and e.payload.get('purpose') == 'experience_distillation'
                       for e in ledger.events('source'))
        if mode == 'valid':
            assert saved['version'] == record['version'] + 1
            assert saved['review_status'] == 'draft'
            assert saved['extraction_method'] == 'model_distillation'
            assert saved['model_receipt']['usage']['total_tokens'] == 12
            assert store.backfill(ledger)['unchanged'] == 1
            reviewed = client.post('/api/v1/experiences/' + record['experience_id'] + '/review',
                json={'decision': 'approve', 'expected_version': saved['version']})
            assert reviewed.status_code == 200
            assert store.search('code_audit', 'Python命令注入')
        elif mode == 'stale':
            assert saved['summary'] == '用户在模型返回前手动修正了概要'
        else:
            assert saved['version'] == record['version']
            assert saved['summary'] == record['summary']
        assert ledger.verify('source')


async def test_demo_or_revoked_version_does_not_count_as_used(settings):
    ledger = LedgerStore(settings.database_url)
    store = ExperienceStore(ledger.engine)
    item = note(store)
    item = store.review(item['experience_id'], 'approve', item['version'])
    gateway = ModelGateway(settings)
    try:
        orchestrator = SecurityOrchestrator(settings, ledger, gateway, ToolBroker(default_registry(), Guardrail()), experiences=store)
        state = AgentState(run_id='demo', task=TaskRequest(objective='Python命令注入'), scenario=Scenario.CODE_AUDIT)
        retrieved = await orchestrator._retrieve_context({'agent': state.model_dump(mode='json')})
        await orchestrator._plan(retrieved)
        assert store.uses(item['experience_id']) == []
        store.review(item['experience_id'], 'retire', item['version'])
        result = await orchestrator._plan(retrieved)
        assert result['agent']['knowledge_hits'] == []
    finally:
        await gateway.close()


def test_stale_experience_hit_cannot_be_recorded_as_used(settings):
    from security_agent.schemas import KnowledgeHit

    store = ExperienceStore(settings.database_url)
    item = note(store)
    approved = store.review(item['experience_id'], 'approve', item['version'])
    hit = KnowledgeHit(memory_id=approved['experience_id'], version=str(approved['version']),
                       content=store.context(approved), source='experience', confidence=1.0)
    store.review(approved['experience_id'], 'retire', approved['version'])
    assert store.record_use('later-run', hit) is None
    assert store.get(approved['experience_id'])['usage_count'] == 0


def test_api_preview_edit_review_and_failed_distill_preserve_content(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        content = {'title': 'Python命令注入经验', 'summary': 'subprocess需要参数数组', 'module_route': 'code_audit',
            'conditions': ['Python调用subprocess'], 'lessons': ['不启用shell'], 'steps': [], 'limitations': [], 'tags': ['Python']}
        created = client.post('/api/v1/experiences', json=content).json()['experience']
        assert client.get('/api/v1/experiences/search', params={'module_route': 'code_audit', 'q': 'Python命令注入'}).json()['experiences'] == []
        review = client.post('/api/v1/experiences/' + created['experience_id'] + '/review', json={'decision': 'approve', 'expected_version': created['version']})
        assert review.status_code == 200
        found = client.get('/api/v1/experiences/search', params={'module_route': 'code_audit', 'q': 'Python命令注入'}).json()
        assert found['counted_as_usage'] is False and len(found['experiences']) == 1
        detail = client.get('/api/v1/experiences/' + created['experience_id']).json()
        assert detail['uses'] == [] and len(detail['history']) == 2
        state = source_run(app.state.service.ledger)
        assert client.get('/api/v1/runs/source/experience-uses').json() == {'uses': []}
        assert client.get('/api/v1/runs/missing/experience-uses').status_code == 404
        record = extract(app.state.experiences, app.state.service.ledger, state)
        response = client.post('/api/v1/experiences/' + record['experience_id'] + '/distill')
        assert response.status_code == 503
        assert app.state.experiences.get(record['experience_id'])['version'] == record['version']
