// Operator-selectable network access presets.
//
// Single source of truth for the network limits an operator may choose in the
// UI.  Each preset mirrors an authorization policy enforced by the backend
// (security_agent/bounded_http.py, session_http.py, ...), so the option an
// operator picks carries exactly the constraint string the task records.
// Adding a policy is one entry here plus its backend module.

export const STATIC_ONLY_CONSTRAINT = '仅允许只读静态分析'

export const NETWORK_POLICY_PRESETS = [
  {
    value: 'read_only_http',
    label: '授权 URL 的 GET/HEAD 只读探测',
    constraint: '仅允许对授权 URL 发起 GET/HEAD 只读请求，不发送请求体或跟随跳转',
    description: '只读取页面与接口响应的侦察类题目。',
  },
  {
    value: 'bounded_http',
    label: '授权 URL 的 GET/HEAD/POST 受限请求（请求体 ≤ 4 KB，适合 RFI/上传类题目）',
    constraint: '仅允许对授权 URL 发起 GET/HEAD/POST 请求；请求体不超过 4 KB，不自定义请求头或 Cookie，不跟随跳转',
    description: '可投递请求体，但不带 Cookie；专项上限为每意图 120 次、每任务 400 次，且仍受任务总预算约束。需要登录态的题目请改用会话预设。',
  },
  {
    value: 'session_http',
    label: '授权 URL 的 GET/HEAD/POST + 会话 Cookie（登录态业务题）',
    constraint: '仅允许对授权 URL 发起 GET/HEAD/POST 请求；请求体不超过 4 KB，可携带会话 Cookie 与受限请求头，不跟随跳转',
    description: '允许复用目标下发的会话 Cookie 与受限请求头，没有专项调用次数上限，仍受任务总时间和调用预算约束。',
  },
  {
    value: 'none',
    label: '仅本地静态分析',
    constraint: STATIC_ONLY_CONSTRAINT,
    description: '不访问目标网络。',
  },
]

export const NETWORK_POLICY_VALUES = NETWORK_POLICY_PRESETS.map((item) => item.value)

export function networkPolicyPreset(value) {
  return NETWORK_POLICY_PRESETS.find((item) => item.value === value) || null
}

export function networkPolicyOptions(values = NETWORK_POLICY_VALUES) {
  return NETWORK_POLICY_PRESETS
    .filter((item) => values.includes(item.value))
    .map(({ value, label }) => ({ value, label }))
}

// Pick the default policy for a freshly classified task.  An explicit preset
// constraint the operator typed wins; otherwise a penetration task that kept
// the static-only default starts from read-only reconnaissance.
export function defaultNetworkPolicyFor({ primaryType, constraints = '' } = {}) {
  const text = String(constraints || '').trim()
  const preset = NETWORK_POLICY_PRESETS
    .find((item) => item.value !== 'none' && item.constraint === text)
  if (preset) return preset.value
  return primaryType === 'penetration' && text === STATIC_ONLY_CONSTRAINT ? 'read_only_http' : 'none'
}

// The constraint text a task should carry for the chosen policy: a preset
// constraint replaces the static-only default, custom operator text is kept.
export function constraintForNetworkPolicy(policy, constraints) {
  const text = String(constraints ?? '').trim()
  const preset = networkPolicyPreset(policy)
  if (preset && text === STATIC_ONLY_CONSTRAINT) return preset.constraint
  return text
}
