export const roleCatalog = [
  { id: 'interpreter', name: '任务解释智能体', shortName: '解释', description: '识别任务场景、输入类型与授权范围', events: ['scenario.classified'] },
  { id: 'planner', name: '规划智能体', shortName: '规划', description: '生成并校验有界执行计划', events: ['plan.created', 'plan.validated', 'step.selected'] },
  { id: 'analyst', name: '分析智能体', shortName: '分析', description: '规范化工具观测、Finding 与 Evidence', events: ['analysis.completed'] },
  { id: 'verifier', name: '验证智能体', shortName: '验证', description: '检查证据引用与结论闭环', events: ['verification.completed'] },
  { id: 'reporter', name: '报告智能体', shortName: '报告', description: '生成审计报告并提交记忆候选', events: ['report.generated', 'memory.candidate'] },
]

export const eventLabels = {
  'knowledge.planner_consumed': '经验已注入模型规划', 'experience.distilled': '经验模型提炼完成',
  'run.queued': '任务进入队列', 'run.created': '建立运行上下文', 'input.ingested': '输入材料入库',
  'scenario.classified': '识别安全场景', 'knowledge.retrieved': '检索知识上下文', 'plan.created': '生成执行计划',
  'plan.validated': '校验执行计划', 'step.selected': '选择执行步骤', 'guardrail.evaluated': '执行安全策略检查',
  'approval.requested': '请求人工审批', 'approval.resolved': '审批处理完成', 'tool.started': '调用安全工具',
  'tool.completed': '安全工具执行完成', 'observation.recorded': '记录工具观测', 'analysis.completed': '分析安全发现',
  'verification.completed': '验证分析结论', 'reflection.completed': '反思与有限重试', 'report.generated': '生成安全报告',
  'memory.candidate': '提交记忆候选', 'report.refreshed': '刷新最新任务结果', 'run.failed': '运行失败',
  'penetration.status': '渗透探索状态更新', 'penetration.terminal': '渗透项目进入终态',
  'exploration.updated': '探索路径实时更新', 'exploration.completed': '探索路径完成',
  'agent.started': '智能体开始工作', 'agent.instruction': '编排器下发指令',
  'agent.thought': '智能体思考摘要', 'agent.completed': '智能体完成节点',
  'agent.failed': '智能体节点失败', 'llm.stream.started': '模型开始流式生成',
  'llm.stream.delta': '模型增量输出', 'llm.stream.completed': '模型流式输出完成', 'llm.stream.failed': '模型流式输出失败',
}

export const categoryFor = (type = '') => type.startsWith('agent.') || type.startsWith('llm.') ? 'agent' : type.includes('tool') ? 'tool' : type.includes('approval') || type.includes('guardrail') ? 'security' : type.includes('verification') ? 'verification' : type.includes('report') || type.includes('memory') ? 'report' : type.includes('plan') || type.includes('step') || type.includes('exploration') || type.includes('penetration') ? 'planning' : 'runtime'

export function projectSecurityEvents(events = []) {
  const actions = { allow: '放行', deny: '拦截', require_approval: '要求审批', approve: '批准', approved: '批准', denied: '拒绝', reject: '拒绝', requested: '待审批' }
  return dedupeEvents(events).filter((event) => {
    const type = event.event_type || ''
    return categoryFor(type) === 'security' || type.startsWith('mcp.approval.') || type === 'tool.unavailable' || type === 'blackboard.interrupted'
  }).map((event) => {
    const payload = event.payload || {}
    const rawAction = payload.action || payload.decision || payload.status || event.event_type.split('.').at(-1)
    return {
      event_id: event.event_id,
      sequence: event.sequence,
      timestamp: event.timestamp,
      event_type: event.event_type,
      action: actions[rawAction] || rawAction,
      risk_level: payload.risk_level,
      tool: payload.tool_name || payload.tool,
      policy_ids: Array.isArray(payload.policy_ids) ? payload.policy_ids.filter(value => typeof value === 'string') : [],
      reason: payload.reason || payload.error || event.summary || '',
    }
  })
}

export function projectEvent(event) {
  return { ...event, title: eventLabels[event.event_type] || event.event_type, category: categoryFor(event.event_type), summary: event.summary || event.payload?.summary || event.payload?.reason || '' }
}

export function getVerifiedOutputs(report) {
  return Array.isArray(report?.verified_outputs)
    ? [...new Set(report.verified_outputs.filter((value) => typeof value === 'string' && value.trim()))]
    : []
}

export async function copyVerifiedOutput(value, writeText = (text) => navigator.clipboard.writeText(text)) {
  await writeText(value)
}

// Reconnects may replay a frame and ledger pagination may repeat a boundary.
// Use both durable event_id and monotonic sequence to keep projections stable.
export function dedupeEvents(events = []) {
  const ids = new Set()
  const sequences = new Set()
  return events.filter((event) => {
    if (event?.event_id && ids.has(event.event_id)) return false
    if (Number.isFinite(event?.sequence) && sequences.has(event.sequence)) return false
    if (event?.event_id) ids.add(event.event_id)
    if (Number.isFinite(event?.sequence)) sequences.add(event.sequence)
    return true
  })
}

export function mergeLedgerEvents(ledgerEvents = [], liveEvents = []) {
  return dedupeEvents([...ledgerEvents, ...liveEvents]
    .sort((left, right) => (left.sequence || 0) - (right.sequence || 0)))
}

// Lifecycle events belong to a call. Keep one row per receipt, including
// failures before execution and terminal events received before their start.
export function projectToolCalls(events = []) {
  const calls = new Map()
  const legacyPending = new Map()
  for (const event of mergeLedgerEvents(events)) {
    const type = event.event_type || ''
    const mcp = type.startsWith('mcp.call.')
    if (!mcp && !['tool.started', 'tool.completed'].includes(type)) continue
    const payload = event.payload || {}
    if (mcp && !payload.call_id) continue
    const name = payload.tool || payload.tool_name
    const started = type.endsWith('.started')
    let key = payload.call_id ? `${mcp ? 'mcp' : 'tool'}:${payload.call_id}` : null
    if (!key) {
      if (!name) continue
      const pending = legacyPending.get(name) || []
      key = started ? `tool:event:${event.event_id || event.sequence}` : pending.shift()
      if (!key) key = `tool:event:${event.event_id || event.sequence}`
      if (started) pending.push(key)
      legacyPending.set(name, pending)
    }
    const call = calls.get(key) || { id: key, metadata: {}, terminal: false }
    call.metadata = started
      ? { ...payload, ...call.metadata }
      : { ...call.metadata, ...payload }
    if (started) {
      call.timestamp = payload.started_at || event.timestamp || call.timestamp
      if (!call.terminal) call.status = payload.status || 'running'
    } else {
      call.terminal = true
      call.status = payload.status || (mcp ? type.slice('mcp.call.'.length) : 'unknown')
      call.duration = payload.duration_ms ?? call.duration
    }
    call.timestamp ||= payload.started_at || event.timestamp
    calls.set(key, call)
  }
  return [...calls.values()].map((call) => {
    const payload = call.metadata
    const elapsed = new Date(payload.completed_at) - new Date(payload.started_at)
    const error = payload.error_message || payload.error
    return {
      id: call.id,
      tool: call.id.startsWith('mcp:')
        ? `${payload.server_id || 'MCP'} / ${payload.tool || payload.tool_name || '未知工具'}`
        : payload.tool || payload.tool_name || '未知工具',
      description: payload.call_id
        ? payload.blackboard?.intent_id
          ? `黑板意图 ${payload.blackboard.intent_id} · 回执 ${payload.call_id}`
          : `调用回执 ${payload.call_id}`
        : '任务账本记录的实际工具调用',
      version: payload.tool_version,
      status: call.status,
      timestamp: call.timestamp,
      duration: call.duration ?? (Number.isFinite(elapsed) ? Math.max(0, elapsed) : null),
      error: typeof error === 'string' ? error.split(/\r?\n/)[0] : '',
      placeholder: false,
    }
  }).sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp))
}

export function projectStreams(events) {
  const streams = new Map()
  const messages = []
  for (const event of dedupeEvents(events)) {
    const payload = event.payload || {}
    if (event.event_type === 'agent.instruction') messages.push({ ...event, kind: 'instruction', content: payload.content, agent: payload.agent_id })
    if (event.event_type === 'agent.thought') messages.push({ ...event, kind: 'thought', content: payload.summary, agent: payload.agent_id })
    if (!event.event_type.startsWith('llm.')) continue
    const traceId = payload.trace_id
    if (!traceId) continue
    const current = streams.get(traceId) || { traceId, content: '', status: 'starting', seen: new Set(), startSequence: event.sequence, sequence: event.sequence, stage: payload.stage, model: payload.model }
    current.stage = payload.stage || current.stage; current.model = payload.model || current.model; current.sequence = event.sequence
    if (event.event_type === 'llm.stream.started') current.status = 'streaming'
    if (event.event_type === 'llm.stream.delta') {
      const key = payload.index ?? event.sequence
      if (!current.seen.has(key)) {
        current.seen.add(key)
        current.content = typeof payload.content === 'string' ? payload.content : current.content + (payload.delta || '')
      }
      current.status = 'streaming'
    }
    if (event.event_type === 'llm.stream.completed') {
      current.status = 'completed'
      current.usage = payload.usage
      if (typeof payload.content === 'string') current.content = payload.content
    }
    if (event.event_type === 'llm.stream.failed') { current.status = 'failed'; current.content = payload.message || '模型调用失败，已切换到安全降级路径。' }
    streams.set(traceId, current)
  }
  const modelStreams = [...streams.values()].map(({ seen, ...item }) => ({ ...item, kind: 'model' }))
  return [...messages, ...modelStreams].sort((left, right) => left.sequence - right.sequence)
}

const thoughtStageLabels = {
  interpreter: '理解任务与输入',
  planner: '规划执行路径',
  analyst: '分析工具结果',
  verifier: '验证证据闭环',
  reporter: '形成最终结论',
}

const milestoneLabels = {
  'analysis.completed': '完成安全分析',
  'verification.completed': '完成证据验证',
  'report.generated': '生成任务报告',
  'report.refreshed': '刷新任务最新结果',
  'memory.candidate': '评估记忆候选',
  'run.failed': '任务执行失败',
}

function payloadSummary(payload = {}) {
  if (payload.summary || payload.reason || payload.error) return payload.summary || payload.reason || payload.error
  const details = []
  if (payload.status) details.push(`状态：${{ success: '成功', completed: '已完成', error: '错误', failed: '失败', partial: '部分完成', denied: '已拒绝' }[payload.status] || payload.status}`)
  if (Number.isFinite(payload.finding_count)) details.push(`发现 ${payload.finding_count} 项`)
  if (Number.isFinite(payload.evidence_count)) details.push(`证据 ${payload.evidence_count} 条`)
  if (Number.isFinite(payload.duration_ms)) details.push(`耗时 ${(payload.duration_ms / 1000).toFixed(2)} 秒`)
  return details.join('，')
}

export function projectThoughtTimeline(events, runStatus) {
  const ordered = dedupeEvents(events).sort((left, right) => left.sequence - right.sequence)
  const items = []
  const toolStarts = new Map()
  const streams = projectStreams(ordered).filter((item) => item.kind === 'model')

  for (const event of ordered) if (event.event_type === 'tool.started') toolStarts.set(event.payload?.tool, event)

  const objective = ordered.find((event) => event.event_type === 'run.queued')
  if (objective) items.push({ id: objective.event_id, sequence: objective.sequence, kind: 'objective', title: '理解用户任务', content: objective.payload?.objective || '任务已进入执行队列。', timestamp: objective.timestamp })

  for (const event of ordered) {
    const payload = event.payload || {}
    if (event.event_type === 'agent.instruction') {
      const boundary = ordered.find((candidate) => candidate.sequence > event.sequence
        && candidate.event_type === 'agent.instruction')?.sequence ?? Number.POSITIVE_INFINITY
      const matching = ordered.filter((candidate) => candidate.sequence > event.sequence
        && candidate.sequence < boundary
        && candidate.payload?.agent_id === payload.agent_id
        && candidate.payload?.node === payload.node)
      const thought = matching.find((candidate) => candidate.event_type === 'agent.thought')
      const completed = matching.find((candidate) => ['agent.completed', 'agent.failed'].includes(candidate.event_type))
      const stepStreams = streams.filter((stream) => stream.startSequence > event.sequence && stream.startSequence < boundary)
      const successfulStreams = stepStreams.filter((stream) => stream.status !== 'failed')
      const visibleStreams = successfulStreams.length ? successfulStreams : stepStreams.slice(-1)
      items.push({
        id: event.event_id,
        sequence: event.sequence,
        kind: 'thought',
        title: thoughtStageLabels[payload.agent_id] || `${payload.agent_id || 'Agent'} 思考`,
        content: payload.content || '执行当前编排节点。',
        detail: thought?.payload?.summary,
        process: visibleStreams.map((stream) => ({ id: stream.traceId, content: stream.content, model: stream.model, status: stream.status, usage: stream.usage })),
        active: !completed,
        failed: completed?.event_type === 'agent.failed',
        agent: payload.agent_id,
        node: payload.node,
        timestamp: event.timestamp,
      })
    }
    if (event.event_type === 'tool.completed') {
      const started = toolStarts.get(payload.tool)
      items.push({ id: event.event_id, sequence: event.sequence, kind: payload.status === 'success' ? 'tool' : 'failed', title: `调用 ${payload.tool || '受控工具'}`, content: payloadSummary(payload) || '工具调用已经结束。', detail: started?.payload?.args ? `参数：${JSON.stringify(started.payload.args)}` : '', coverage: payload.coverage, timestamp: event.timestamp })
    }
    if (milestoneLabels[event.event_type]) items.push({ id: event.event_id, sequence: event.sequence, kind: event.event_type === 'run.failed' ? 'failed' : event.event_type === 'report.generated' ? 'conclusion' : 'result', title: milestoneLabels[event.event_type], content: payloadSummary(payload) || eventLabels[event.event_type], timestamp: event.timestamp })
  }

  const firstTime = ordered[0]?.timestamp ? new Date(ordered[0].timestamp).getTime() : 0
  const lastTime = ordered.at(-1)?.timestamp ? new Date(ordered.at(-1).timestamp).getTime() : firstTime
  const durationSeconds = firstTime && lastTime ? Math.max(1, Math.round((lastTime - firstTime) / 1000)) : 0
  const terminal = ['completed', 'partial', 'failed', 'denied'].includes(runStatus)
  return { items: items.sort((left, right) => left.sequence - right.sequence), durationSeconds, terminal }
}

export function deriveNetwork(events, runStatus) {
  const lifecycle = events.filter((event) => event.event_type.startsWith('agent.') && event.payload?.agent_id)
  if (lifecycle.length) {
    const latestByAgent = new Map()
    for (const event of lifecycle) latestByAgent.set(event.payload.agent_id, event)
    const roles = roleCatalog.map((role) => {
      const event = latestByAgent.get(role.id)
      const status = !event ? 'idle' : event.event_type === 'agent.started' || event.event_type === 'agent.instruction' || event.event_type === 'agent.thought' ? 'active' : event.event_type === 'agent.failed' ? 'failed' : 'completed'
      return { ...role, status, node: event?.payload?.node, activity: event?.payload?.summary || event?.payload?.content || event?.payload?.instruction }
    })
    const lastActive = [...lifecycle].reverse().find((event) => {
      const isActive = ['agent.started', 'agent.instruction', 'agent.thought'].includes(event.event_type)
      return isActive && latestByAgent.get(event.payload.agent_id) === event
    })
    return { roles, active: lastActive?.payload.agent_id || null, activeNode: lastActive?.payload.node || null, completed: roles.filter((role) => role.status === 'completed').length }
  }
  const seenTypes = new Set(events.map((event) => event.event_type)); const latestType = events.at(-1)?.event_type || ''
  const terminal = ['completed', 'partial', 'failed', 'denied'].includes(runStatus)
  const roles = roleCatalog.map((role) => { const touched = role.events.some((type) => seenTypes.has(type)); const latest = role.events.includes(latestType); return { ...role, status: latest && !terminal ? 'active' : touched ? 'completed' : 'idle' } })
  const active = roles.find((role) => role.status === 'active')?.id || null
  return { roles, active, completed: roles.filter((role) => role.status === 'completed').length }
}

export const formatTime = (value) => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
export const compactId = (value, size = 12) => value ? String(value).slice(0, size) : '—'
