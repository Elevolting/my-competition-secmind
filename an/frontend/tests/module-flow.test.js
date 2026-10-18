import test from 'node:test'
import assert from 'node:assert/strict'
import { projectModuleFlow } from '../src/app/moduleFlowModel.js'

test('MCP execution displays the task tool and evidence flow', () => {
  const nodes = projectModuleFlow({ module_route: 'penetration', routing: { execution_backend: 'mcp' } }, [
    { event_type: 'tool.completed', payload: { status: 'success' } },
    { event_type: 'analysis.completed', payload: {} },
  ])
  assert.equal(nodes.find(n => n.label === '工具分析').complete, true)
  assert.equal(nodes.some(n => n.label === 'Worker'), false)
})

test('model stream volume never completes tool or verification stages', () => {
  const events = Array.from({ length: 100 }, (_, i) => ({ event_type: 'llm.stream.delta', payload: { index: i } }))
  const nodes = projectModuleFlow({ scenario: 'code_audit', status: 'running' }, events)
  assert.ok(nodes.every((node) => !node.complete))
})

test('successful tools and failed verification remain independently visible', () => {
  const nodes = projectModuleFlow({ status: 'partial' }, [
    { event_type: 'tool.completed', payload: { status: 'success' } },
    { event_type: 'verification.completed', payload: { error: 'missing evidence', route: 'report' } },
    { event_type: 'report.generated', payload: { status: 'partial' } },
  ])
  assert.equal(nodes[3].complete, true)
  assert.equal(nodes[5].complete, false)
  assert.equal(nodes[6].complete, true)
})

test('submission and seed facts do not imply worker execution or goal completion', () => {
  const nodes = projectModuleFlow({ module_route: 'penetration', external_execution: {
    project_id: 'p', fact_count: 2, intent_count: 1, status: 'running', objective_reached: false,
  } })
  assert.deepEqual(nodes.map((node) => node.complete), [true, true, false, false, false])
})

test('goal requires a successful terminal status and objective evidence', () => {
  const get = (status, reached) => projectModuleFlow({ scenario: 'penetration_test',
    external_execution: { status, objective_reached: reached } }).at(-1).complete
  assert.equal(get('running', true), false)
  assert.equal(get('completed', false), false)
  assert.equal(get('completed', true), true)
})
