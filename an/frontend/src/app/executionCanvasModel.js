export const STATUS = { waiting: '待执行', running: '执行中', exploring: '执行中', approval: '等待审批', completed: '完成', failed: '失败', cancelled: '取消', timeout: '超时', known: '已知', confirmed: '已确认', candidate: '候选', pending: '待验证', ruled_out: '已排除', insufficient: '证据不足', active: '摘要生效', superseded: '摘要已失效' }
export const TERMINAL = new Set(['completed', 'cancelled', 'failed', 'timeout'])
export const ACTIVE = new Set(['running', 'exploring'])
const FINISHED_RUNS = new Set(['completed', 'partial', 'failed', 'denied', 'cancelled'])
const FINISHED_PROJECTS = new Set(['completed', 'partial', 'failed', 'stopped', 'cancelled'])
export const isExecutionFinished = (runStatus, projectStatus) => FINISHED_RUNS.has(runStatus) || FINISHED_PROJECTS.has(projectStatus)

export function executionElapsed(node, now, runStatus, projectStatus) {
  const history = node.execution_history || []
  const claimed = history.find((item) => item.attempt_id === node.attempt_id &&
    ['runtime.claimed', 'blackboard.intent.started'].includes(item.event_type))
  const started = claimed?.timestamp || node.created_at
  if (!started) return ''

  const finished = TERMINAL.has(node.status) || isExecutionFinished(runStatus, projectStatus)
  const ended = node.concluded_at || (finished ? node.latest_activity : now)
  if (!ended) return ''
  const seconds = Math.max(0, Math.floor((new Date(ended).getTime() - new Date(started).getTime()) / 1000))
  return Number.isFinite(seconds) ? `${Math.floor(seconds / 60)}分${seconds % 60}秒` : ''
}
const short = (value, max = 70) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, max)
export const isIntent = (node) => ['intent', 'hypothesis', 'conclusion'].includes(node.type)
const nodeLabel = (node) => {
  const kind = isIntent(node) ? '验证想法' : node.type === 'digest' ? '冷节点摘要' : node.type === 'origin' ? '起点' : node.type === 'goal' ? '目标' : node.type === 'item' ? (node.item_type === 'finding' ? '漏洞候选' : '事实条目') : '结果包'
  const title = short(node.title || node.label || node.description, 34)
  const metadata = isIntent(node)
    ? `${short(node.worker || '未领取', 16)} · ${short(node.current_tool || (ACTIVE.has(node.status) ? '暂无工具记录' : STATUS[node.status]), 18)}`
    : node.items?.length ? `${node.items.length} 条结果 · 点击展开` : ''
  return `${kind} · ${STATUS[node.status] || node.status || '待执行'}\n${title.slice(0, 17)}${title.length > 17 ? '\n' + title.slice(17) : ''}${metadata ? '\n' + metadata : ''}`
}

export function projectElements(graph, expanded, query, showHistory = true) {
  const nodes = []
  const edges = []
  const q = query.trim().toLocaleLowerCase()
  const covers = (graph.edges || []).filter((edge) => edge.relation === 'covers' || edge.type === 'covers')
  const coveredBy = new Map()
  for (const edge of covers) if (!coveredBy.has(edge.target)) coveredBy.set(edge.target, edge.source)
  const matches = (node) => !q || [node.title, node.label, node.description, node.raw_id, ...(node.items || []).map((item) => `${item.title} ${item.summary} ${item.id} ${(item.evidence_ids || []).join(" ")}`)].join(' ').toLocaleLowerCase().includes(q)
  const visible = new Set()
  for (const node of graph.nodes || []) {
    if (node.type === 'hint' || node.type === 'worker') continue
    const digestId = coveredBy.get(node.id)
    const covered = Boolean(digestId) && !expanded.has(digestId) && !q
    if (!covered && matches(node) && (q || showHistory || node.type === 'digest' || (isIntent(node) && !TERMINAL.has(node.status)) || ['origin', 'goal'].includes(node.type))) visible.add(node.id)
    if (q && matches(node) && digestId) visible.add(digestId)
  }
  if (!q && !showHistory) {
    for (const edge of graph.edges || []) {
      if (visible.has(edge.source) && isIntent((graph.nodes || []).find((node) => node.id === edge.source) || {})) visible.add(edge.target)
    }
  }
  // Search includes every ancestor, independent of edge ordering.
  let added = true
  while (added) {
    added = false
    for (const edge of graph.edges || []) {
      if (visible.has(edge.target) && !visible.has(edge.source)) { visible.add(edge.source); added = true }
    }
  }
  for (const node of graph.nodes || []) {
    if (!visible.has(node.id) || node.type === 'hint' || node.type === 'worker') continue
    nodes.push({ group: 'nodes', data: { ...node, display: nodeLabel(node) }, classes: `kind-${isIntent(node) ? 'intent' : node.type} state-${node.status}` })
    if (expanded.has(node.id) || (q && (node.items || []).some((item) => `${item.title} ${item.summary} ${item.id} ${(item.evidence_ids || []).join(" ")}`.toLocaleLowerCase().includes(q)))) {
      for (const item of node.items || []) {
        const id = `item:${node.raw_id}:${item.id}`
        nodes.push({ group: 'nodes', data: { ...item, id, raw_id: item.id, type: 'item', item_type: item.type,
          parent_fact_id: node.raw_id, status: item.verification_status || 'known', display: nodeLabel({ ...item, type: 'item', item_type: item.type, status: item.verification_status || 'known' }) },
          classes: `kind-item state-${item.verification_status || 'known'}` })
        edges.push({ group: 'edges', data: { id: `${node.id}:${id}`, source: node.id, target: id, relation: 'contains' }, classes: 'edge-contains' })
      }
    }
  }
  const ids = new Set(nodes.map((node) => node.data.id))
  for (const edge of graph.edges || []) {
    if ((edge.relation === 'covers' || edge.type === 'covers') && !expanded.has(edge.source) && !q) continue
    if (ids.has(edge.source) && ids.has(edge.target)) edges.push({ group: 'edges', data: edge, classes: `edge-${edge.type || 'source'} ${edge.status === 'running' ? 'edge-running' : edge.status === 'approval' ? 'edge-approval' : ''}` })
  }
  return [...nodes, ...edges]
}
