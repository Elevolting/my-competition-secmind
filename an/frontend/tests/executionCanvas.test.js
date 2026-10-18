import assert from 'node:assert/strict'
import test from 'node:test'
import { executionElapsed, projectElements } from '../src/app/executionCanvasModel.js'
const fixture = () => {
  const nodes = [{ id: 'fact:origin', raw_id: 'origin', type: 'origin', title: '入口', status: 'known' }]
  const edges = []
  for (let i = 0; i < 30; i++) {
    nodes.push({ id: `intent:i${i}`, raw_id: `i${i}`, type: 'intent', title: `验证想法 ${i}`, status: i < 3 ? 'running' : 'completed' })
    nodes.push({ id: `fact:f${i}`, raw_id: `f${i}`, type: 'fact', title: `结果包 ${i}`, status: 'completed', items: Array.from({ length: 10 }, (_, j) => ({ id: `item-${j}`, type: j === 9 ? 'finding' : 'fact', title: `条目 ${i}-${j}`, summary: '观察结果', evidence_ids: [`evidence-${i}-${j}`] })) })
    edges.push({ id: `produce-${i}`, source: `intent:i${i}`, target: `fact:f${i}` }, { id: `source-${i}`, source: 'fact:origin', target: `intent:i${i}` })
  }
  return { nodes, edges: edges.reverse() }
}
test('300 result items stay bundled and expansion IDs never collide', () => {
  const graph = fixture()
  assert.equal(projectElements(graph, new Set(), '').filter(e => e.group === 'nodes').length, 61)
  const expanded = projectElements(graph, new Set(graph.nodes.map(n => n.id)), '')
  assert.equal(expanded.filter(e => e.group === 'nodes').length, 361)
  assert.equal(new Set(expanded.map(e => e.data.id)).size, expanded.length)
})
test('evidence search opens its bundle and includes the full causal ancestry', () => {
  const data = projectElements(fixture(), new Set(), 'evidence-29-9')
  const ids = data.map(e => e.data.id)
  assert.ok(ids.includes('fact:origin'))
  assert.ok(ids.includes('intent:i29'))
  assert.ok(ids.includes('fact:f29'))
  assert.ok(ids.includes('item:f29:item-9'))
  assert.ok(!ids.includes('intent:i28'))
})

test('cancelled intent freezes at its last activity when concluded_at is absent', () => {
  const node = {
    status: 'cancelled', attempt_id: 'attempt-1', created_at: '2026/10/14 2:23:25',
    latest_activity: '2026/10/14 11:41:39',
    execution_history: [{ event_type: 'runtime.claimed', attempt_id: 'attempt-1', timestamp: '2026/10/14 11:40:21' }],
  }
  assert.equal(executionElapsed(node, Date.parse('2026-10-14T08:00:00Z'), 'partial', 'stopped'), '1分18秒')
  assert.equal(executionElapsed(node, Date.parse('2026-10-15T08:00:00Z'), 'partial', 'stopped'), '1分18秒')
})

test('finished runs freeze stale nodes; live nodes still count up', () => {
  const node = { status: 'running', created_at: '2026-10-14T03:00:00Z', latest_activity: '2026-10-14T03:01:00Z' }
  assert.equal(executionElapsed(node, Date.parse('2026-10-14T03:05:00Z'), 'partial', 'stopped'), '1分0秒')
  assert.equal(executionElapsed(node, Date.parse('2026-10-14T03:06:00Z'), 'running', 'active'), '6分0秒')
  assert.equal(executionElapsed({ ...node, status: 'failed', latest_activity: null }, Date.now(), 'failed', 'stopped'), '')
})
