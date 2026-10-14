import test from 'node:test'
import assert from 'node:assert/strict'
import { defaultTaskBudget, retryTaskBudget, validTaskBudget } from '../src/app/task-budget.js'

const config = {
  defaults: { max_runtime_seconds: 1800, penetration_max_runtime_seconds: 7200, max_tool_calls: 600, max_model_calls: 200, penetration_max_model_calls: 600 },
  limits: { max_runtime_seconds: { min: 60, max: 7200 }, max_tool_calls: { min: 1, max: 100000 }, max_model_calls: { min: 1, max: 10000 } },
}

test('creation reads the server defaults for penetration, code audit and reverse', () => {
  assert.equal(defaultTaskBudget(config, 'penetration').max_runtime_seconds, 7200)
  assert.equal(defaultTaskBudget(config, 'penetration').max_model_calls, 600)
  for (const route of ['code_audit', 'reverse']) {
    assert.deepEqual(defaultTaskBudget(config, route), { max_runtime_seconds: 1800, max_tool_calls: 600, max_model_calls: 200 })
  }
})

test('cleared, fractional and out-of-range budgets prevent submission', () => {
  const budget = defaultTaskBudget(config, 'penetration')
  assert.equal(validTaskBudget(budget, config.limits), true)
  for (const [key, value] of [['max_tool_calls', null], ['max_tool_calls', 0], ['max_model_calls', 1.5], ['max_runtime_seconds', 7260]]) {
    assert.equal(validTaskBudget({ ...budget, [key]: value }, config.limits), false)
  }
})

test('retry suggests exploration defaults for legacy budgets without changing the source', () => {
  const run = { module_route: 'penetration', budget: { max_runtime_seconds: 2400, runtime_seconds_used: 2400, max_tool_calls: 12, max_model_calls: 20 } }
  const before = structuredClone(run)
  assert.deepEqual(retryTaskBudget(run, config), { max_runtime_seconds: 7200, max_tool_calls: 600, max_model_calls: 600 })
  assert.deepEqual(run, before)
})

test('retry preserves larger configured call budgets and clamps time to API limits', () => {
  const run = { module_route: 'code_audit', budget: { max_runtime_seconds: 6000, runtime_seconds_used: 6000, max_tool_calls: 1200, max_model_calls: 400 } }
  assert.deepEqual(retryTaskBudget(run, config), { max_runtime_seconds: 7200, max_tool_calls: 1200, max_model_calls: 400 })
})
