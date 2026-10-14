import test from 'node:test'
import assert from 'node:assert/strict'

import { evaluationEventSocketUrl, eventSocketUrl, getPrompt, refreshRunReport, terminalStatus } from '../src/api.js'

test('builds the current run event websocket URL', () => {
  const url = eventSocketUrl('run id', 12, new URL('http://127.0.0.1:5173/workbench'))
  assert.equal(url, 'ws://127.0.0.1:5173/api/v1/runs/run%20id/events?after_sequence=12')
})

test('builds a Test3 evaluation websocket URL', () => {
  const url = evaluationEventSocketUrl('evaluation id', 7, new URL('https://agent.test/workbench'))
  assert.equal(url, 'wss://agent.test/api/v1/evaluations/evaluation%20id/events?after_sequence=7')
})

test('recognizes all backend terminal states', () => {
  for (const status of ['completed', 'partial', 'failed', 'denied']) assert.equal(terminalStatus(status), true)
  for (const status of ['pending', 'running', 'waiting_approval']) assert.equal(terminalStatus(status), false)
})

test('exports the latest-result refresh API used by the workbench', () => {
  assert.equal(typeof refreshRunReport, 'function')
})

test('exports the read-only prompt detail API', () => {
  assert.equal(typeof getPrompt, 'function')
})
