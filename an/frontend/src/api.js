const viteEnv = import.meta.env || {}
const API_BASE = (viteEnv.VITE_API_BASE_URL || '').replace(/\/$/, '')

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(options.headers || {}),
    },
  })
  if (!response.ok) {
    const raw = await response.text()
    let detail = raw
    try {
      detail = JSON.parse(raw).detail || raw
      if (Array.isArray(detail)) detail = detail.map(item => `${(item.loc || []).filter(x => x !== 'body').join('.')}: ${item.msg || '参数无效'}`).join('；')
    } catch {
    }
    const error = new Error(detail || `请求失败 (${response.status})`)
    error.status = response.status
    throw error
  }
  return response.status === 204 ? null : response.json()
}

export const health = () => request('/health')
export const getTaskBudgetDefaults = () => request('/api/v1/task-budget-defaults')
export const getDashboard = () => request(`/api/v1/dashboard?refresh=${Date.now()}`)
export const getModelConfig = () => request('/api/v1/model-config')
// Avoid browser/proxy caching so websocket-triggered refreshes show the latest
// ledger counters and quota consumption immediately.
export const getModelUsage = () => request(`/api/v1/model-usage?refresh=${Date.now()}`)
export const testModelConfig = (payload) => request('/api/v1/model-config/test', { method: 'POST', body: JSON.stringify(payload) })
export const getAvailableModels = (payload) => request('/api/v1/model-config/models', { method: 'POST', body: JSON.stringify(payload) })
export const updateModelUsageQuota = (payload) => request('/api/v1/model-usage/quota', { method: 'PUT', body: JSON.stringify(payload) })
export const updateModelConfig = (payload) => request('/api/v1/model-config', { method: 'PUT', body: JSON.stringify(payload) })
export const getPromptCatalog = () => request('/api/v1/prompts')
export const getPrompt = (promptKey) => request(`/api/v1/prompts/${encodeURIComponent(promptKey)}`)
export const getMcpCatalog = () => request('/api/v1/mcp/catalog')
export const getMcpServer = (serverId) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}`)
export const createMcpServer = (payload) => request('/api/v1/mcp/servers', { method: 'POST', body: JSON.stringify(payload) })
export const updateMcpServer = (serverId, payload) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}`, { method: 'PUT', body: JSON.stringify(payload) })
export const deleteMcpServer = (serverId) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}`, { method: 'DELETE' })
export const createMcpTool = (serverId, payload) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}/tools`, { method: 'POST', body: JSON.stringify(payload) })
export const updateMcpTool = (serverId, toolName, payload) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}/tools/${encodeURIComponent(toolName)}`, { method: 'PUT', body: JSON.stringify(payload) })
export const deleteMcpTool = (serverId, toolName) => request(`/api/v1/mcp/servers/${encodeURIComponent(serverId)}/tools/${encodeURIComponent(toolName)}`, { method: 'DELETE' })
export const getIntegrationStatus = () => request('/api/v1/integration-status')

function socketUrl(path, params = {}, location = window.location) {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const configured = viteEnv.VITE_WS_BASE_URL?.trim()
  const base = configured ? new URL(configured, location.origin) : new URL(location.origin)
  base.protocol = protocol
  base.pathname = path
  base.search = new URLSearchParams(params).toString()
  return base.toString()
}

export const modelUsageSocketUrl = (location = window.location) => socketUrl('/api/v1/model-usage/events', {}, location)
export const listRuns = (params = {}) => request(`/api/v1/runs?${new URLSearchParams({ refresh: String(Date.now()), ...params })}`)
export const getRun = (runId) => request(`/api/v1/runs/${encodeURIComponent(runId)}`)
export const searchRunTraces = (runId, params = {}) => request(`/api/v1/runs/${encodeURIComponent(runId)}/traces?${new URLSearchParams(params)}`)
export const getRunTrace = (runId, traceId) => request(`/api/v1/runs/${encodeURIComponent(runId)}/traces/${encodeURIComponent(traceId)}`)
export const createTrafficEvidence = (runId, payload) => request(`/api/v1/runs/${encodeURIComponent(runId)}/traffic-evidence`, { method: 'POST', body: JSON.stringify(payload) })
export const getTrafficEvidence = (runId, evidenceId) => request(`/api/v1/runs/${encodeURIComponent(runId)}/traffic-evidence/${encodeURIComponent(evidenceId)}`)
export const bindTrafficEvidence = (runId, findingId, payload) => request(`/api/v1/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/traffic-bindings`, { method: 'POST', body: JSON.stringify(payload) })
export const trafficEvidenceExportUrl = (runId, evidenceId) => `${API_BASE}/api/v1/runs/${encodeURIComponent(runId)}/traffic-evidence/${encodeURIComponent(evidenceId)}/export`
export const retryRun = (runId, payload) => request(`/api/v1/runs/${encodeURIComponent(runId)}/retry`, { method: 'POST', body: JSON.stringify(payload) })
export const cancelRun = (runId) => request(`/api/v1/runs/${encodeURIComponent(runId)}/cancel`, { method: 'POST' })
export const submitRunHint = (runId, payload) => request(`/api/v1/runs/${encodeURIComponent(runId)}/hint`, { method: 'POST', body: JSON.stringify(payload) })
export const getReport = (runId) => request(`/api/v1/runs/${encodeURIComponent(runId)}/report`)
export const refreshRunReport = (runId) => request(`/api/v1/runs/${encodeURIComponent(runId)}/report/refresh`, { method: 'POST' })
export const getPenetrationGraph = (runId) =>
  request(`/api/v1/runs/${encodeURIComponent(runId)}/penetration-graph`)
export const getBlackboardGraph = (runId, signal = AbortSignal.timeout(15000)) =>
  request(`/api/v1/runs/${encodeURIComponent(runId)}/blackboard-graph`, { signal })
export const getAssetGraph = (runId, signal = AbortSignal.timeout(15000)) =>
  request(`/api/v1/runs/${encodeURIComponent(runId)}/asset-graph`, { signal })
export const thoughtProcessUrl = (runId) =>
  `${API_BASE}/api/v1/runs/${encodeURIComponent(runId)}/thoughts/export`
export async function getLedger(runId, afterSequence = 0) {
  const events = []
  let cursor = afterSequence
  let chainValid = true
  while (true) {
    const page = await request(`/api/v1/runs/${encodeURIComponent(runId)}/ledger?after_sequence=${cursor}&limit=5000`)
    const next = page.events || []
    events.push(...next)
    chainValid = chainValid && page.chain_valid === true
    const lastSequence = next.at(-1)?.sequence
    if (next.length < 5000 || !Number.isInteger(lastSequence) || lastSequence <= cursor) break
    cursor = lastSequence
  }
  return { schema_version: '1.0', run_id: runId, events, chain_valid: chainValid }
}

export async function uploadFile(file) {
  const body = new FormData()
  body.append('file', file, file.name)
  return request('/api/v1/uploads', { method: 'POST', body })
}

export const createTask = (payload, requestId) =>
  request('/api/v1/tasks', { method: 'POST', body: JSON.stringify(payload), headers: requestId ? { 'X-Request-Id': requestId } : {} })
export const createBatch = (payload, requestId) =>
  request('/api/v1/batches', { method: 'POST', body: JSON.stringify(payload), headers: requestId ? { 'X-Request-Id': requestId } : {} })
export const getBatch = (batchId) => request(`/api/v1/batches/${encodeURIComponent(batchId)}`)
export const getBatchTasks = (batchId) => request(`/api/v1/batches/${encodeURIComponent(batchId)}/tasks`)
export const classifyTask = (payload) =>
  request('/api/v1/tasks/classify', { method: 'POST', body: JSON.stringify(payload) })
export const listModules = () => request('/api/v1/modules')
export const getIncidentStatus = () => request('/api/v1/incident/status')
export const getIncidentCommands = () => request('/api/v1/incident/commands')
export const startIncidentMonitor = () => request('/api/v1/incident/monitor/start', { method: 'POST' })
export const stopIncidentMonitor = () => request('/api/v1/incident/monitor/stop', { method: 'POST' })
export const getIncidentLogs = (limit = 100, offset = 0) => request(`/api/v1/incident/logs?${new URLSearchParams({ limit, offset })}`)
export const getIncidentActions = (limit = 100, offset = 0) => request(`/api/v1/incident/actions?${new URLSearchParams({ limit, offset })}`)
export const getIncidentApprovals = (limit = 100) => request(`/api/v1/incident/approvals?limit=${limit}`)
export const getIncidentPendingApprovals = () => request('/api/v1/incident/pending-approvals')
export const getIncidentEligibleUnblocks = () => request('/api/v1/incident/eligible-unblocks')
export const submitIncidentCommand = (payload) => request('/api/v1/incident/command', { method: 'POST', body: JSON.stringify(payload) })
export const resolveIncidentApproval = (approvalId, payload) => request(`/api/v1/incident/approvals/${encodeURIComponent(approvalId)}`, { method: 'POST', body: JSON.stringify(payload) })
export const incidentEventSocketUrl = (location = window.location) => socketUrl('/api/v1/incident/events', {}, location)
export const listExperiences = (params = {}) => {
  const query = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ''))
  return request(`/api/v1/experiences${query.size ? `?${query}` : ''}`)
}
export const createExperience = (payload) =>
  request('/api/v1/experiences', { method: 'POST', body: JSON.stringify(payload) })
export const deleteExperience = (experienceId) =>
  request(`/api/v1/experiences/${encodeURIComponent(experienceId)}`, { method: 'DELETE' })
export const backfillExperiences = () => request('/api/v1/experiences/backfill', { method: 'POST' })

export const inspectQuestionBank = (payload) =>
  request('/api/v1/question-banks/inspect', { method: 'POST', body: JSON.stringify(payload) })

export const getQuestionBankInspection = (bankId) =>
  request(`/api/v1/question-banks/${encodeURIComponent(bankId)}/inspection`)

export function questionBankEventSocketUrl(bankId, location = window.location) {
  return socketUrl(`/api/v1/question-banks/${encodeURIComponent(bankId)}/events`, {}, location)
}

export const confirmQuestionBank = (bankId, payload) =>
  request(`/api/v1/question-banks/${encodeURIComponent(bankId)}/confirm`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })

export const listBenchmarkTasks = () => request('/api/v1/benchmark/tasks')
export const createEvaluation = (payload) =>
  request('/api/v1/evaluations', { method: 'POST', body: JSON.stringify(payload) })
export const getEvaluation = (evaluationId) =>
  request(`/api/v1/evaluations/${encodeURIComponent(evaluationId)}`)
export const getEvaluationByRun = (runId) =>
  request(`/api/v1/evaluations/by-run/${encodeURIComponent(runId)}`)
export const getEvaluationScore = (evaluationId) =>
  request(`/api/v1/evaluations/${encodeURIComponent(evaluationId)}/score`)
export const evaluationReportUrl = (evaluationId) =>
  `${API_BASE}/api/v1/evaluations/${encodeURIComponent(evaluationId)}/report`

export const submitApproval = (runId, requestId, payload) =>
  request(`/api/v1/runs/${encodeURIComponent(runId)}/approvals/${encodeURIComponent(requestId)}`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })

export const decideMcpApproval = (approvalId, decision) =>
  request(`/api/v1/mcp/approvals/${encodeURIComponent(approvalId)}`, {
    method: 'POST', body: JSON.stringify({ decision }),
  })

export function eventSocketUrl(runId, afterSequence = 0, location = window.location) {
  return socketUrl(`/api/v1/runs/${encodeURIComponent(runId)}/events`, { after_sequence: String(afterSequence) }, location)
}

export function evaluationEventSocketUrl(evaluationId, afterSequence = 0, location = window.location) {
  return socketUrl(
    `/api/v1/evaluations/${encodeURIComponent(evaluationId)}/events`,
    { after_sequence: String(afterSequence) },
    location,
  )
}

export function terminalStatus(status) {
  return ['completed', 'partial', 'failed', 'denied'].includes(status)
}

export const discoverMcp = (id) => request(`/api/v1/mcp/servers/${encodeURIComponent(id)}/discover`, { method: 'POST' })
export const invokeMcp = (id, payload) => request(`/api/v1/mcp/servers/${encodeURIComponent(id)}/invoke`, { method: 'POST', body: JSON.stringify(payload) })
export const updatePrompt = (key, payload) => request(`/api/v1/prompts/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify(payload) })
export const getPromptHistory = (key) => request(`/api/v1/prompts/${encodeURIComponent(key)}/history`)
export const uploadIncidentSample = (file) => { const body = new FormData(); body.append('file', file); return request('/api/v1/incident/samples', { method: 'POST', body }) }
export const incidentEvidenceUrl = (id) => `${API_BASE}/api/v1/incident/evidence/${encodeURIComponent(id)}`

export const getExperience = (id) => request(`/api/v1/experiences/${encodeURIComponent(id)}`)
export const getRunExperienceUses = (id) => request(`/api/v1/runs/${encodeURIComponent(id)}/experience-uses`)
export const editExperience = (id, payload) => request(`/api/v1/experiences/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) })
export const reviewExperience = (id, payload) => request(`/api/v1/experiences/${encodeURIComponent(id)}/review`, { method: 'POST', body: JSON.stringify(payload) })
export const distillExperience = async (id) => {
  try {
    return await request(`/api/v1/experiences/${encodeURIComponent(id)}/distill`, {
      method: 'POST', signal: AbortSignal.timeout(165000),
    })
  } catch (error) {
    if (error.name === 'TimeoutError') throw new Error('AI 提炼等待超时，请刷新经验详情确认是否已保存，再决定是否重试')
    throw error
  }
}
export const searchExperiences = (module, query) => request(`/api/v1/experiences/search?${new URLSearchParams({ module_route: module, q: query })}`)
export const feedbackExperience = (id, payload) => request(`/api/v1/experiences/${encodeURIComponent(id)}/feedback`, { method: 'POST', body: JSON.stringify(payload) })
