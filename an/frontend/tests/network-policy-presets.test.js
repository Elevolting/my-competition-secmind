import test from 'node:test'
import assert from 'node:assert/strict'

import {
  constraintForNetworkPolicy,
  defaultNetworkPolicyFor,
  networkPolicyOptions,
  networkPolicyPreset,
  NETWORK_POLICY_VALUES,
  STATIC_ONLY_CONSTRAINT,
} from '../src/app/network-policy-presets.js'

test('exposes every backend policy as an operator-selectable preset', () => {
  assert.deepEqual(NETWORK_POLICY_VALUES, ['read_only_http', 'bounded_http', 'session_http', 'none'])
  assert.equal(networkPolicyPreset('session_http').constraint, '仅允许对授权 URL 发起 GET/HEAD/POST 请求；请求体不超过 4 KB，可携带会话 Cookie 与受限请求头，不跟随跳转')
})

test('offers the session preset in the selection list', () => {
  const values = networkPolicyOptions().map((item) => item.value)
  assert.ok(values.includes('session_http'))
})

test('defaults a static-only penetration task to read-only reconnaissance', () => {
  assert.equal(defaultNetworkPolicyFor({ primaryType: 'penetration', constraints: STATIC_ONLY_CONSTRAINT }), 'read_only_http')
  assert.equal(defaultNetworkPolicyFor({ primaryType: 'code_audit', constraints: STATIC_ONLY_CONSTRAINT }), 'none')
})

test('honours an explicit preset constraint typed by the operator', () => {
  const session = networkPolicyPreset('session_http').constraint
  assert.equal(defaultNetworkPolicyFor({ primaryType: 'penetration', constraints: session }), 'session_http')
  assert.equal(defaultNetworkPolicyFor({ primaryType: 'penetration', constraints: '只读' }), 'none')
})

test('replaces the static-only default with the chosen preset constraint', () => {
  assert.equal(constraintForNetworkPolicy('session_http', STATIC_ONLY_CONSTRAINT), networkPolicyPreset('session_http').constraint)
  assert.equal(constraintForNetworkPolicy('none', STATIC_ONLY_CONSTRAINT), STATIC_ONLY_CONSTRAINT)
  assert.equal(constraintForNetworkPolicy('bounded_http', '自定义约束'), '自定义约束')
})
