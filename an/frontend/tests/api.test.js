import test from 'node:test'
import assert from 'node:assert/strict'

import { bindTrafficEvidence, createTrafficEvidence, evaluationEventSocketUrl, eventSocketUrl,
  getPrompt, getRunTrace, getTrafficEvidence, refreshRunReport, searchRunTraces,
  terminalStatus, trafficEvidenceExportUrl } from '../src/api.js'

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

test('execution trace routes encode task, trace and search parameters', async () => {
  const original = globalThis.fetch
  const paths = []
  globalThis.fetch = async (path) => {
    paths.push(path)
    return { ok: true, status: 200, json: async () => ({ items: [] }) }
  }
  try {
    await searchRunTraces('run id', { keyword: 'a&b', cursor: 4 })
    await getRunTrace('run id', 'trace/id')
    assert.equal(paths[0], '/api/v1/runs/run%20id/traces?keyword=a%26b&cursor=4')
    assert.equal(paths[1], '/api/v1/runs/run%20id/traces/trace%2Fid')
  } finally { globalThis.fetch = original }
})

test('traffic evidence routes encode task, finding and evidence identifiers', async () => {
  const original = globalThis.fetch
  const paths = []
  globalThis.fetch = async (path) => {
    paths.push(path)
    return { ok: true, status: 201, json: async () => ({ evidence_id: 'evidence/1' }) }
  }
  try {
    await createTrafficEvidence('run id', { source_kind: 'har', source_ref: 'capture.har' })
    await getTrafficEvidence('run id', 'evidence/1')
    await bindTrafficEvidence('run id', 'finding/1', { evidence_id: 'evidence/1', role: 'proof' })
    assert.deepEqual(paths, [
      '/api/v1/runs/run%20id/traffic-evidence',
      '/api/v1/runs/run%20id/traffic-evidence/evidence%2F1',
      '/api/v1/runs/run%20id/findings/finding%2F1/traffic-bindings',
    ])
    assert.equal(trafficEvidenceExportUrl('run id', 'evidence/1'),
      '/api/v1/runs/run%20id/traffic-evidence/evidence%2F1/export')
  } finally { globalThis.fetch = original }
})
