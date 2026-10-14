import test from 'node:test'
import assert from 'node:assert/strict'
import { incidentFeedback } from '../src/app/incidentFeedback.js'

test('denied response never reports execution as completed', () => {
  assert.deepEqual(incidentFeedback({ action: { status: 'denied' }, approval: { status: 'denied' } }),
    { level: 'info', text: '审批已拒绝，动作未执行' })
})

test('incident response distinguishes pending approval, failed execution and upload', () => {
  assert.equal(incidentFeedback({ approval: { status: 'pending' } }).text, '已进入审批队列，尚未执行')
  assert.equal(incidentFeedback({ action: { status: 'failed', error: 'Access denied' } }).text, 'Access denied')
  assert.equal(incidentFeedback({ path: 'sample.bin' }, 'upload').text, '上传完成，文件尚未隔离')
})
