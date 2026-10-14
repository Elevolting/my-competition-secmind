import test from 'node:test'
import assert from 'node:assert/strict'

import { copyVerifiedOutput, dedupeEvents, deriveNetwork, getVerifiedOutputs, mergeLedgerEvents, projectSecurityEvents, projectStreams, projectThoughtTimeline, projectToolCalls } from '../src/app/runtimeModel.js'
import { localizeFinding, localizeModelOutput, localizePublicText, severityLabels } from '../src/app/localization.js'
import { classifyRunStatus, isSuccessfulRun, routeFor, summarizeRunStatuses } from '../src/app/runStatus.js'
import { reconcileBlackboardElements, updateSelectedBlackboardNode } from '../src/app/blackboardModel.js'

test('completed MCP task does not wait for a Security Runtime project', () => {
  const run = { status: 'completed', module_route: 'penetration', routing: { execution_backend: 'mcp' } }
  assert.equal(isSuccessfulRun(run), true)
  assert.equal(classifyRunStatus(run), 'completed')
  assert.equal(isSuccessfulRun({ ...run, status: 'partial' }), false)
  assert.equal(isSuccessfulRun({ ...run, routing: {} }), false)
})

const event = (sequence, event_type, payload) => ({
  event_id: `event-${sequence}`,
  sequence,
  event_type,
  payload,
})

test('shows one row per MCP receipt and retains the terminal result', () => {
  const callId = 'receipt-1'
  const started = { ...event(1, 'mcp.call.started', {
    call_id: callId, server_id: 'local-yakit', tool: 'http_fuzzer',
    status: 'running', started_at: '2026-10-14T12:00:00Z',
    blackboard: { intent_id: 'i001' },
  }), timestamp: '2026-10-14T12:00:00Z' }
  const done = { ...event(2, 'mcp.call.completed', {
    call_id: callId, server_id: 'local-yakit', tool: 'http_fuzzer',
    status: 'completed', started_at: '2026-10-14T12:00:00Z',
    completed_at: '2026-10-14T12:00:03Z',
  }), timestamp: '2026-10-14T12:00:03Z' }
  assert.deepEqual(projectToolCalls([started, done, started]), [{
    id: 'mcp:receipt-1', tool: 'local-yakit / http_fuzzer',
    description: '黑板意图 i001 · 回执 receipt-1', version: undefined,
    status: 'completed', timestamp: '2026-10-14T12:00:00Z',
    duration: 3000, error: '', placeholder: false,
  }])
  assert.equal(projectToolCalls([done, started])[0].status, 'completed')
})

test('keeps a failed MCP receipt with no start event and displays its error', () => {
  const calls = projectToolCalls([event(3, 'mcp.call.failed', {
    call_id: 'failed-1', server_id: 'local-tscanplus', tool: 'upsert_fact',
    status: 'failed', error: "'fact_key' is a required property\nSchema details",
  })])
  assert.equal(calls.length, 1)
  assert.equal(calls[0].status, 'failed')
  assert.equal(calls[0].error, "'fact_key' is a required property")
})

test('pairs normal tool events by call ID', () => {
  const calls = projectToolCalls([
    event(1, 'tool.started', { call_id: 'one', tool: 'scanner' }),
    event(2, 'tool.completed', { call_id: 'one', tool: 'scanner', status: 'success', duration_ms: 500 }),
  ])
  assert.equal(calls.length, 1)
  assert.equal(calls[0].duration, 500)
  assert.equal(calls[0].status, 'success')
})

test('projects the active agent from live lifecycle events and clears it at completion', () => {
  const started = [
    event(1, 'agent.started', { agent_id: 'interpreter', node: 'ingest' }),
    event(2, 'agent.instruction', { agent_id: 'interpreter', node: 'ingest', content: 'ingest' }),
  ]
  const active = deriveNetwork(started, 'running')
  assert.equal(active.active, 'interpreter')
  assert.equal(active.activeNode, 'ingest')
  assert.equal(active.roles.find((role) => role.id === 'interpreter').status, 'active')

  const completed = deriveNetwork([
    ...started,
    event(3, 'agent.completed', { agent_id: 'interpreter', node: 'ingest' }),
  ], 'running')
  assert.equal(completed.active, null)
  assert.equal(completed.roles.find((role) => role.id === 'interpreter').status, 'completed')
})

test('merges a stale ledger snapshot with events already received by websocket', () => {
  const ledger = [event(1, 'run.queued', {})]
  const live = [event(2, 'tool.started', { tool: 'scanner' })]
  assert.deepEqual(mergeLedgerEvents(ledger, live).map((item) => item.sequence), [1, 2])
})

test('assembles model deltas and exposes terminal stream failures', () => {
  const trace = 'trace-1'
  const projected = projectStreams([
    event(1, 'llm.stream.started', { trace_id: trace, stage: 'planner', model: 'model-a' }),
    event(2, 'llm.stream.delta', { trace_id: trace, index: 1, delta: '{"answer":' }),
    event(3, 'llm.stream.delta', { trace_id: trace, index: 2, delta: '"ok"}' }),
    event(4, 'llm.stream.completed', { trace_id: trace, usage: { prompt_tokens: 4, completion_tokens: 2 } }),
    event(5, 'llm.stream.failed', { trace_id: 'trace-2', model: 'model-b', message: 'model unavailable' }),
  ])
  assert.equal(projected[0].content, '{"answer":"ok"}')
  assert.equal(projected[0].status, 'completed')
  assert.equal(projected[0].usage.prompt_tokens, 4)
  assert.equal(projected[1].status, 'failed')
  assert.equal(projected[1].content, 'model unavailable')
})

test('projects raw ledger events into a compact auditable thought timeline', () => {
  const projected = projectThoughtTimeline([
    { ...event(1, 'run.queued', { objective: 'audit source' }), timestamp: '2026-08-13T00:00:00Z' },
    event(2, 'agent.instruction', { agent_id: 'planner', node: 'plan', content: 'create a bounded plan' }),
    event(3, 'llm.stream.started', { trace_id: 'trace', stage: 'planner', model: 'model-a' }),
    event(4, 'llm.stream.delta', { trace_id: 'trace', index: 1, delta: 'public model output' }),
    event(5, 'llm.stream.completed', { trace_id: 'trace', usage: { prompt_tokens: 4 } }),
    event(6, 'agent.thought', { agent_id: 'planner', node: 'plan', summary: 'one safe tool step' }),
    event(7, 'tool.started', { tool: 'bandit', args: { target: '.' } }),
    { ...event(8, 'tool.completed', { tool: 'bandit', status: 'success', duration_ms: 800 }), timestamp: '2026-08-13T00:00:03Z' },
  ], 'completed')
  assert.equal(projected.terminal, true)
  assert.equal(projected.durationSeconds, 3)
  assert.equal(projected.items.filter((item) => item.kind === 'model').length, 0)
  assert.equal(projected.items.find((item) => item.kind === 'thought').process.length, 1)
  assert.equal(projected.items.find((item) => item.kind === 'thought').detail, 'one safe tool step')
  assert.match(projected.items.find((item) => item.kind === 'tool').content, /成功/)
})

test('nests the current public stream under its step and hides a corrected failed attempt', () => {
  const projected = projectThoughtTimeline([
    event(1, 'agent.instruction', { agent_id: 'planner', node: 'plan', content: 'plan safely' }),
    event(2, 'llm.stream.started', { trace_id: 'failed-trace', stage: 'planner', model: 'model-a' }),
    event(3, 'llm.stream.delta', { trace_id: 'failed-trace', index: 1, delta: 'obsolete sentence' }),
    event(4, 'llm.stream.failed', { trace_id: 'failed-trace', message: 'retrying' }),
    event(5, 'llm.stream.started', { trace_id: 'final-trace', stage: 'planner', model: 'model-b' }),
    event(6, 'llm.stream.delta', { trace_id: 'final-trace', index: 1, delta: 'draft sentence' }),
    event(7, 'llm.stream.completed', { trace_id: 'final-trace', content: 'corrected sentence' }),
    event(8, 'agent.thought', { agent_id: 'planner', node: 'plan', summary: 'final summary' }),
    event(9, 'agent.completed', { agent_id: 'planner', node: 'plan' }),
  ], 'completed')
  const step = projected.items.find((item) => item.kind === 'thought')
  assert.equal(step.process.length, 1)
  assert.equal(step.process[0].content, 'corrected sentence')
  assert.equal(step.detail, 'final summary')
  assert.equal(step.active, false)
})

test('localizes historical report findings and public AI summaries', () => {
  const finding = localizeFinding({
    rule_id: 'AUDIT-JAVA-SSTI',
    title: 'User-controlled input reaches a server-side template parser',
    description: 'Request input reaches template parsing.',
  })
  assert.equal(finding.title, '用户可控输入进入服务端模板解析器')
  assert.match(finding.description, /服务端模板注入/)
  assert.equal(severityLabels.CRITICAL, '严重')
  assert.match(localizePublicText('Bandit completed with 2 finding(s).'), /发现 2 个安全问题/)
  assert.match(localizeModelOutput(JSON.stringify({ steps: [{ tool_candidates: ['workspace_security_audit'] }] })), /1 个候选执行步骤/)
})

test('projects verified outputs and copies the selected flag value', async () => {
  assert.deepEqual(getVerifiedOutputs({ verified_outputs: ['ctfshow{fixture}', '', 'ctfshow{fixture}', 1] }), ['ctfshow{fixture}'])
  assert.deepEqual(getVerifiedOutputs({}), [])
  let copied = ''
  await copyVerifiedOutput('ctfshow{fixture}', async (value) => { copied = value })
  assert.equal(copied, 'ctfshow{fixture}')
})

test('blackboard refresh preserves dragged positions and keeps selected node details open', () => {
  const refreshed = [{ group: 'nodes', data: { id: 'fact-1', label: 'updated fact' }, position: { x: 300, y: 120 } }]
  const current = [{ group: 'nodes', data: { id: 'fact-1', label: 'old fact' }, position: { x: 815, y: 240 } }]
  assert.deepEqual(reconcileBlackboardElements(refreshed, current)[0].position, { x: 815, y: 240 })
  assert.deepEqual(reconcileBlackboardElements(refreshed, current, true)[0].position, { x: 300, y: 120 })
  assert.deepEqual(updateSelectedBlackboardNode({ id: 'fact-1', label: 'old fact' }, [{ id: 'fact-1', label: 'updated fact' }]), { id: 'fact-1', label: 'updated fact' })
  assert.equal(updateSelectedBlackboardNode({ id: 'fact-1' }, []), null)
})

test('deduplicates live events by event_id and sequence while preserving order', () => {
  const first = event(1, 'llm.stream.delta', { trace_id: 'trace', index: 1, delta: 'a' })
  const duplicateId = { ...first, sequence: 2 }
  const duplicateSequence = { ...event(3, 'llm.stream.delta', { trace_id: 'trace', index: 2, delta: 'b' }), sequence: 1 }
  assert.deepEqual(dedupeEvents([first, duplicateId, duplicateSequence]).map((item) => item.event_id), ['event-1'])
})

test('projects guardrail and approval events without exposing tool arguments', () => {
  const projected = projectSecurityEvents([
    event(1, 'guardrail.evaluated', { action: 'require_approval', risk_level: 2, tool_name: 'mcp:scanner', parameters: { secret: 'hidden' } }),
    event(2, 'approval.requested', { reason: 'needs operator approval', parameters: { token: 'hidden' } }),
    event(3, 'tool.completed', { tool: 'safe-tool', args: { password: 'hidden' } }),
  ])
  assert.equal(projected.length, 2)
  assert.equal(projected[0].tool, 'mcp:scanner')
  assert.equal(projected[0].action, '要求审批')
  assert.equal(JSON.stringify(projected).includes('hidden'), false)
})

test('requires verified Security Runtime objective evidence before counting penetration as completed', () => {
  const base = { status: 'completed', module_route: 'penetration' }
  assert.equal(isSuccessfulRun({ ...base, external_execution: { status: 'running', objective_reached: false } }), false)
  assert.equal(classifyRunStatus({ ...base, external_execution: { status: 'timeout', objective_reached: false } }), 'timeout')
  assert.equal(classifyRunStatus({ ...base, external_execution: { status: 'unavailable', objective_reached: false } }), 'unavailable')
  assert.equal(isSuccessfulRun({ ...base, external_execution: { status: 'completed', objective_reached: true } }), true)
})

test('normalizes legacy routes and keeps overview status buckets mutually exclusive', () => {
  assert.equal(routeFor({ module_route: 'audit', scenario: 'code_audit' }), 'code_audit')
  assert.equal(routeFor({ module_route: 'audit', scenario: 'penetration_test' }), 'penetration')
  assert.equal(routeFor({ module_route: 'reverse_triage' }), 'reverse')
  assert.deepEqual(summarizeRunStatuses([
    { status: 'completed', module_route: 'code_audit' },
    { status: 'partial', module_route: 'code_audit' },
    { status: 'failed', module_route: 'code_audit' },
    { status: 'completed', module_route: 'penetration', external_execution: { status: 'timeout' } },
    { status: 'completed', module_route: 'penetration', external_execution: { status: 'running' } },
  ]), { completed: 1, partial: 1, failed: 1, timeout: 1, unavailable: 0, waiting_approval: 0, running: 1 })
})
