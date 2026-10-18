import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const source = await readFile(new URL('../src/security_runtime/dispatcher/workers/adapters/pi_blackboard.ts', import.meta.url), 'utf8');
const { default: register } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const catalog = [
  { name: 'http', description: 'TscanPlus / http_request: send an HTTP request', version: 'v1', inputSchema: { type: 'object', required: ['url'] } },
  { name: 'scan', description: 'Kali / nmap_scan: scan an authorized host', version: 'v2', inputSchema: { type: 'object', required: ['target'] } },
  { name: 'decode', description: 'Burp / base64_decode: decode text', version: 'v3', inputSchema: { type: 'object', required: ['text'] } },
];

async function setup(t, invoke, model, limit = '12') {
  const cwd = process.cwd();
  const workspace = await mkdtemp(join(tmpdir(), 'secmind-bridge-test-'));
  const fetch = globalThis.fetch;
  const env = { SECMIND_WORKBENCH_URL: 'http://workbench.test', SECMIND_PROJECT_ID: 'project', SECMIND_INTENT_ID: 'intent', SECMIND_WORKER_NAME: 'worker', SECMIND_MAX_TOOL_CALLS: limit, SECMIND_ATTEMPT_ID: 'attempt-test', SECMIND_MODEL_BUDGET: model ? 'required' : 'legacy' };
  const previous = Object.fromEntries(Object.keys(env).map((name) => [name, process.env[name]]));
  Object.assign(process.env, env);
  process.chdir(workspace);
  t.after(async () => {
    globalThis.fetch = fetch;
    process.chdir(cwd);
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    await rm(workspace, { recursive: true, force: true });
  });
  globalThis.fetch = async (url, options) => {
    if (url.includes('/tools?')) return { ok: true, json: async () => ({ tools: catalog }) };
    if (url.endsWith('/invoke')) return { ok: true, json: async () => invoke(JSON.parse(options.body)) };
    if (model && url.includes('/model/')) return model(url, JSON.parse(options.body));
    throw new Error(`Unexpected request: ${url}`);
  };
  const registered = new Map();
  register({ registerTool: (tool) => registered.set(tool.name, tool), on: (name, handler) => registered.set(name, handler) });
  return registered;
}

test('discovery exposes all services compactly and returns a full schema only on selection', async (t) => {
  const tools = await setup(t, () => { throw new Error('Discovery must not execute security tools'); });
  const discover = async (params) => JSON.parse((await tools.get('blackboard_tools').execute('call', params)).content[0].text);
  const directory = await discover({});
  assert.equal(directory.available_count, 3);
  assert.deepEqual(directory.tools.map((tool) => tool.name), ['http', 'scan', 'decode']);
  assert.ok(directory.tools.every((tool) => !('inputSchema' in tool)));
  assert.deepEqual((await discover({ query: 'KALI scan' })).tools.map((tool) => tool.name), ['scan']);
  assert.deepEqual((await discover({ tool: 'scan' })).tools, [catalog[1]]);
  assert.deepEqual((await discover({ query: 'missing capability' })).tools, []);
});

test('round budget stops actual invocations and preserves complete evidence outside the preview', async (t) => {
  let invocations = 0;
  const tools = await setup(t, (payload) => {
    invocations += 1;
    assert.equal(payload.version, 'v1');
    assert.equal(payload.worker, 'worker');
    return { call_id: '00000000-0000-4000-8000-000000000001', status: 'completed', result: { body: 'x'.repeat(9000), evidence: 'preserved tail' } };
  });
  const invoke = tools.get('blackboard_invoke');
  let response;
  for (let i = 0; i < 12; i += 1) response = await invoke.execute('call', { tool: 'http', arguments: { url: 'http://authorized.test' } });
  assert.equal(invocations, 12);
  assert.match(response.content[0].text, /Round budget exhausted/);
  assert.match(response.content[0].text, /preview truncated/);
  assert.ok(response.content[0].text.length < 9000);
  const receipt = JSON.parse(await readFile(join(process.cwd(), '.mcp-results/00000000-0000-4000-8000-000000000001.json'), 'utf8'));
  assert.equal(receipt.result.evidence, 'preserved tail');
  const blocked = await invoke.execute('call', { tool: 'scan', arguments: { target: 'authorized.test' } });
  assert.equal(blocked.isError, true);
  assert.equal(invocations, 12);
});

test('unavailable tools are rejected before invocation', async (t) => {
  const tools = await setup(t, () => { throw new Error('Unavailable tool was executed'); });
  await assert.rejects(tools.get('blackboard_invoke').execute('call', { tool: 'unknown', arguments: {} }), /unavailable/);
});

test('unset or zero round count lets Dispatcher timeouts govern exploration past twelve calls', async (t) => {
  for (const limit of ['', '0']) {
    await t.test(`limit=${limit || 'unset'}`, async (t) => {
      let invocations = 0;
      const tools = await setup(t, () => {
        invocations += 1;
        return { call_id: '00000000-0000-4000-8000-000000000003', status: 'completed', result: { body: 'ok' } };
      }, undefined, limit);
      for (let i = 0; i < 15; i += 1) {
        const result = await tools.get('blackboard_invoke').execute('call', { tool: 'http', arguments: {} });
        assert.equal(result.isError, false);
        assert.match(result.content[0].text, /Round time is controlled by Dispatcher/);
        assert.doesNotMatch(result.content[0].text, /Round budget exhausted/);
      }
      assert.equal(invocations, 15);
    });
  }
});

test('invalid explicit round limit refuses worker setup', async (t) => {
  for (const limit of ['-1', '1.5', 'invalid']) {
    await t.test(limit, async (t) => {
      await assert.rejects(setup(t, () => {}, undefined, limit), /nonnegative integer/);
    });
  }
});

test('lost tool responses and running receipts reuse one request identity', async (t) => {
  const requests = [];
  const tools = await setup(t, (payload) => {
    requests.push(payload.request_id);
    if (requests.length === 1) throw new Error('Response lost');
    return { call_id: '00000000-0000-4000-8000-000000000002', status: requests.length === 2 ? 'running' : 'completed', result: { body: 'ok' } };
  });
  const result = await tools.get('blackboard_invoke').execute('call', { tool: 'http', arguments: { url: 'http://authorized.test' } });
  assert.equal(new Set(requests).size, 1);
  assert.equal(requests.length, 3);
  assert.equal(result.isError, false);
});

test('model reservations and usage receipts replay the same identity after response loss', async (t) => {
  const seen = { reserve: [], complete: [] };
  const tools = await setup(t, () => { throw new Error('No tools expected'); }, async (url, payload) => {
    const kind = url.endsWith('/reserve') ? 'reserve' : 'complete';
    seen[kind].push(payload);
    assert.equal(payload.attempt_id, 'attempt-test');
    if (seen[kind].length === 1) throw new Error('Response lost');
    return { ok: true, json: async () => ({ completed: true }) };
  });
  const ctx = { abort: () => assert.fail('Unexpected abort') };
  await tools.get('before_provider_request')({}, ctx);
  await tools.get('message_end')({ message: { role: 'toolResult' } }, ctx);
  assert.equal(seen.complete.length, 0);
  const event = { message: { role: 'assistant', usage: { input: 5, cacheRead: 2, cacheWrite: 1, output: 3 } } };
  await tools.get('message_end')(event, ctx);
  await tools.get('message_end')(event, ctx);
  assert.equal(seen.reserve.length, 2);
  assert.equal(seen.complete.length, 2);
  assert.equal(seen.reserve[0].request_id, seen.complete[0].request_id);
  assert.deepEqual(seen.complete[0], seen.complete[1]);
  assert.deepEqual(seen.complete[0].usage, { prompt_tokens: 8, completion_tokens: 3, cache_read_tokens: 2 });
});

test('reservation refusal aborts before the SDK can issue a model request', async (t) => {
  let aborted = false;
  const tools = await setup(t, () => { throw new Error('No tools expected'); }, async () => ({
    ok: false, json: async () => ({ detail: 'budget exhausted' }),
  }));
  const originalExit = process.exit;
  t.after(() => { process.exit = originalExit; });
  process.exit = (code) => { assert.equal(code, 72); throw new Error('Worker exited'); };
  await assert.rejects(tools.get('before_provider_request')({}, { abort: () => { aborted = true; } }), /Worker exited/);
  assert.equal(aborted, true);
});
