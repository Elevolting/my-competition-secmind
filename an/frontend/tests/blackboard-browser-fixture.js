// Injected before the application by blackboard-browser.py. All API traffic is
// isolated from the running workbench; this fixture never starts a real task.
window.__blackboardQA = { graphDelay: 700, runDelay: 7000, graphActive: 0, graphMax: 0, graphCalls: 0, ledgerCursors: [], sockets: [], errors: [], hangGraph: false, graphRevision: 0 };
const qa = window.__blackboardQA;
window.addEventListener('error', (event) => qa.errors.push(event.message));
const nativeFetch = window.fetch.bind(window);
const nativeTimeout = AbortSignal.timeout.bind(AbortSignal);
AbortSignal.timeout = (milliseconds) => nativeTimeout(qa.hangGraph ? 100 : milliseconds);
const fixtureStarted = new Date(Date.now() - 45000).toISOString();
const event = (sequence) => ({ sequence, event_id: `event-${sequence}`, event_type: 'exploration.updated', timestamp: '2026-10-12T00:00:00Z', payload: {}, actor: 'test' });
const run = (id) => ({ schema_version: '1.0', run_id: id, name: `Test ${id}`, status: 'running', scenario: 'penetration_test', module_route: 'penetration', routing: {}, current_step: 0, total_steps: 1, input_artifact_count: 1, external_execution: { project_id: `project-${id}`, status: 'active', objective_reached: false }, budget: {}, mcp_pending_approvals: [] });
const delay = (milliseconds, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) return reject(signal.reason);
  const timer = setTimeout(done, milliseconds);
  function done() { signal?.removeEventListener('abort', aborted); resolve(); }
  function aborted() { clearTimeout(timer); reject(signal.reason); }
  signal?.addEventListener('abort', aborted, { once: true });
});
window.WebSocket = class {
  constructor() { qa.sockets.push(this); this.readyState = 1; setTimeout(() => this.onopen?.(), 0); }
  close() { this.readyState = 3; }
};
qa.emit = (sequence) => qa.sockets.filter((socket) => socket.readyState === 1).forEach((socket) => socket.onmessage?.({ data: JSON.stringify(event(sequence)) }));
window.fetch = async (input, options = {}) => {
  const url = new URL(typeof input === 'string' ? input : input.url, location.origin);
  if (!url.pathname.startsWith('/api/') && url.pathname !== '/health') return nativeFetch(input, options);
  let body = {};
  const parts = url.pathname.split('/');
  const id = parts[4];
  if (url.pathname === '/api/v1/runs') body = { runs: [run('run-a'), run('run-b')], total: 2 };
  else if (url.pathname.endsWith('/blackboard-graph')) {
    qa.graphCalls += 1; qa.graphActive += 1; qa.graphMax = Math.max(qa.graphMax, qa.graphActive);
    try { await delay(qa.hangGraph ? 60000 : qa.graphDelay, options.signal); }
    finally { qa.graphActive -= 1; }
    const nodes = [{ id: `node-${id}`, raw_id: 'origin', type: 'origin', title: `Origin ${id}`, status: 'known' }];
    const edges = [];
    const statuses = ['running', 'running', 'approval', 'failed', 'timeout', 'cancelled', 'waiting'];
    for (let i = 0; i < 30; i++) {
      const status = statuses[i] || 'completed';
      nodes.push({ id: `intent:${id}:${i}`, raw_id: `i${i}`, type: 'intent', title: `验证登录分支 ${i}`, description: `验证登录分支 ${i} 的安全边界`, status, worker: 'worker-' + (i % 2), attempt_id: `a-${i}`, current_tool: i < 2 ? 'http_probe' : null, source_ids: ['origin'], source_relation: 'evidence', success_criteria: '证据可复现', created_at: fixtureStarted, source_links: [{fact_id:'origin',relation:'evidence'}], phase: '验证与收集证据', latest_activity: fixtureStarted, execution_history: [{ event_type:'runtime.claimed', attempt_id:`a-${i}`, timestamp: fixtureStarted }, {event_type:'runtime.tool.started', tool:i < 2 ? 'http_probe' : undefined, status, attempt_id:`a-${i}`, timestamp:fixtureStarted }] });
      nodes.push({ id: `fact:${id}:${i}`, raw_id: `f${i}`, type: 'fact', title: `分支 ${i} 结果包`, description: '保留的原始工具回执', summary: `10 条观察，1 个待验证候选 · ${qa.graphRevision}`, status: 'completed', items: Array.from({length:10}, (_,j) => ({ id: `f${i}:item-${j}`, type: j === 9 ? 'finding' : 'observation', title: `结果条目 ${i}-${j}`, summary:'观察到响应差异，保留证据待验证', evidence_ids: [`evidence-${i}-${j}`], verification_status: j===9 ? 'pending' : null, evidence: [{evidence_id:`evidence-${i}-${j}`, source:'http_probe', summary:'响应差异', artifact_ref:'response.txt'}] })) });
      edges.push({id:`source-${i}`,source:`node-${id}`,target:`intent:${id}:${i}`,status}, {id:`output-${i}`,source:`intent:${id}:${i}`,target:`fact:${id}:${i}`,status:'completed'});
    }
    body = { schema_version:'1.1', linked: true, available: true, project_id: `project-${id}`, project: {status:'active'}, nodes, edges, result_items:nodes.flatMap(n=>n.items || []) };
    // A compact, representative screenshot after the 300-item regression.
    if (qa.presentation) {
      const origin = nodes[0]; origin.title = '发现 /login 接口'; origin.summary = 'POST · 登录入口与请求参数已记录';
      const idea = (i) => nodes.find(n => n.id === `intent:${id}:${i}`);
      const fact = (i) => nodes.find(n => n.id === `fact:${id}:${i}`);
      idea(0).title = '验证登录是否存在 SQL 注入'; idea(0).status = 'completed'; idea(0).current_tool = null;
      idea(0).description = '对登录参数进行受限探测，记录异常响应及对照请求。';
      fact(0).title = '观察到异常响应'; fact(0).items = fact(0).items.slice(0, 2); fact(0).summary = '2 条观察 · 异常响应与对照请求';
      idea(1).title = '验证异常是否由注入触发'; idea(1).description = '根据已记录的异常响应进行重复验证，排除网络波动和业务错误。';
      idea(1).source_ids = ['f0']; idea(1).source_links = [{fact_id:'f0',relation:'evidence'}]; idea(1).success_criteria = '异常可稳定复现，且与对照请求存在一致差异';
      fact(1).title = '漏洞候选：等待证据验证'; fact(1).items = fact(1).items.slice(9); fact(1).summary = '1 个候选 · 工具成功不代表漏洞确认';
      idea(2).title = '验证上传接口的访问权限'; idea(2).description = '等待授权范围审批后验证上传接口的权限边界。';
      idea(6).title = '检查登录接口的请求限速'; idea(6).status = 'running'; idea(6).current_tool = 'http_probe';
      body.nodes = [origin, idea(0), fact(0), idea(1), fact(1), idea(2), idea(6)];
      body.edges = [
        {id:'p0',source:origin.id,target:idea(0).id,status:'completed'},
        {id:'p1',source:idea(0).id,target:fact(0).id,status:'completed'},
        {id:'p2',source:fact(0).id,target:idea(1).id,status:'running'},
        {id:'p3',source:idea(1).id,target:fact(1).id,status:'completed'},
        {id:'p4',source:origin.id,target:idea(2).id,status:'approval'},
        {id:'p5',source:origin.id,target:idea(6).id,status:'running'},
      ];
      body.result_items = body.nodes.flatMap(n => n.items || []);
    }
  } else if (url.pathname.endsWith('/ledger')) {
    const cursor = Number(url.searchParams.get('after_sequence') || 0);
    qa.ledgerCursors.push({ id, cursor });
    await delay(800);
    body = { events: Array.from({ length: Math.max(0, (cursor === 0 ? 3 : 10) - cursor) }, (_, i) => event(cursor + i + 1)), chain_valid: true };
  } else if (url.pathname.match(/^\/api\/v1\/runs\/[^/]+$/)) {
    await delay(qa.runDelay); qa.runDelay = 10; body = run(id);
  } else if (url.pathname === '/api/v1/modules') body = { modules: [] };
  else if (url.pathname === '/health') body = { status: 'ok' };
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
};
