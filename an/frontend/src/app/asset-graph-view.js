const HOST_TYPES = new Set(['domain', 'subdomain', 'ip', 'company', 'app'])

export const assetStatusLabel = (status) => ({
  scoped: '授权范围', invoked: '已调用', discovered: '工具发现', input: '输入材料',
})[status] || '来源待核对'

export function assetKindLabel(type) {
  return ({ company: '授权目标', domain: '域名', subdomain: '子域名', ip: 'IP 地址',
    service: 'Web 服务', app: '应用', endpoint: '接口端点', artifact: '输入材料', bundle: '端点集合' })[type] || '资产'
}

export function assetShortName(node) {
  const raw = String(node?.label || node?.rawId || '')
  if (node?.type === 'endpoint') {
    try { const url = new URL(raw); return `${url.pathname || '/'}${url.search}` }
    catch { return raw }
  }
  return raw
}

export function assetIndex(graph) {
  const nodes = new Map((graph?.nodes || []).map((node) => [node.id, node]))
  const parents = new Map()
  const children = new Map()
  for (const edge of graph?.edges || []) {
    if (!nodes.has(edge.source) || !nodes.has(edge.target)) continue
    if (!parents.has(edge.target)) parents.set(edge.target, [])
    if (!children.has(edge.source)) children.set(edge.source, [])
    parents.get(edge.target).push(edge.source)
    children.get(edge.source).push(edge.target)
  }
  return { nodes, parents, children }
}

export function focusRoot(index, nodeId) {
  if (!index.nodes.size) return null
  const start = index.nodes.get(nodeId) || [...index.nodes.values()].find((item) => item.type !== 'artifact') || [...index.nodes.values()][0]
  if (start.type === 'artifact') return start.id
  const queue = [start.id]
  const seen = new Set()
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const current = queue[cursor]
    if (seen.has(current)) continue
    seen.add(current)
    if (HOST_TYPES.has(index.nodes.get(current)?.type)) return current
    queue.push(...(index.parents.get(current) || []))
  }
  return assetPath(index, start.id)[0]?.id || start.id
}

export function assetPath(index, nodeId) {
  const path = []
  const seen = new Set()
  let current = nodeId
  while (current && index.nodes.has(current) && !seen.has(current)) {
    seen.add(current)
    path.unshift(index.nodes.get(current))
    current = (index.parents.get(current) || []).find((id) => !seen.has(id))
  }
  return path
}

export function relatedCalls(node, calls = []) {
  if (!node) return []
  const raw = String(node.rawId || node.label || '')
  if (!raw) return []
  return calls.filter((call) => (call.target_values || []).some((value) => {
    const target = String(value)
    if (target === raw) return true
    try {
      const url = new URL(target.includes('://') ? target : `http://${target}`)
      if (['domain', 'subdomain', 'ip'].includes(node.type)) return url.hostname.toLowerCase() === raw.toLowerCase()
      const assetUrl = new URL(raw)
      if (node.type === 'service') return assetUrl.origin === url.origin
      if (node.type === 'endpoint') return assetUrl.origin === url.origin && assetUrl.pathname === url.pathname && assetUrl.search === url.search
    } catch { return false }
    return false
  }))
}

export function projectAssetView(graph, rootId, expandedServices = [], selectedId = null, limit = 4) {
  const index = assetIndex(graph)
  const root = index.nodes.get(rootId) ? rootId : focusRoot(index, selectedId)
  if (!root) return { nodes: [], edges: [], root: null, hiddenCount: 0, bundles: [] }
  const expanded = new Set(expandedServices)
  const reachable = new Set([root])
  const queue = [root]
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    for (const child of index.children.get(queue[cursor]) || []) {
      if (!reachable.has(child)) { reachable.add(child); queue.push(child) }
    }
  }
  const bundles = []
  const candidates = new Map()
  let hiddenCount = 0
  for (const id of [...reachable]) {
    const parent = index.nodes.get(id)
    if (parent?.type !== 'service') continue
    const endpoints = [...new Set(index.children.get(id) || [])].filter((child) => reachable.has(child) && index.nodes.get(child)?.type === 'endpoint' && !index.children.get(child)?.length)
    if (endpoints.length <= limit || expanded.has(id) || endpoints.includes(selectedId)) continue
    candidates.set(id, endpoints)
  }
  const hidden = new Set()
  for (const endpoints of candidates.values()) {
    for (const endpoint of endpoints) {
      if ((index.parents.get(endpoint) || []).filter((id) => reachable.has(id)).every((id) => candidates.has(id))) hidden.add(endpoint)
    }
  }
  for (const [id, endpoints] of candidates) {
    const grouped = endpoints.filter((endpoint) => hidden.has(endpoint))
    if (!grouped.length) continue
    const bundleId = `bundle:${id}`
    bundles.push({ id: bundleId, type: 'bundle', label: `${grouped.length} 个接口端点`, rawId: `${grouped.length} 个接口端点`,
      status: 'grouped', parentId: id, count: grouped.length, endpointIds: grouped })
  }
  for (const endpoint of hidden) reachable.delete(endpoint)
  hiddenCount = hidden.size
  // Keep all explicit upstream references without expanding sibling hosts.
  const ancestors = [...reachable]
  for (let cursor = 0; cursor < ancestors.length; cursor += 1) {
    for (const parent of index.parents.get(ancestors[cursor]) || []) {
      if (!reachable.has(parent)) { reachable.add(parent); ancestors.push(parent) }
    }
  }
  const nodes = [...reachable].map((id) => index.nodes.get(id)).filter(Boolean).concat(bundles)
  const edges = (graph?.edges || []).filter((edge) => reachable.has(edge.source) && reachable.has(edge.target))
  for (const bundle of bundles) edges.push({ id: `group:${bundle.parentId}`, source: bundle.parentId, target: bundle.id, type: 'grouped', label: '包含' })
  return { nodes, edges, root, hiddenCount, bundles }
}

export function assetDirectory(graph, query = '', filter = 'all') {
  const term = query.trim().toLocaleLowerCase()
  const order = { company: 0, domain: 1, subdomain: 2, ip: 3, app: 4, service: 5, endpoint: 6, artifact: 7 }
  return (graph?.nodes || []).filter((node) =>
    (filter === 'all' || node.status === filter) &&
    (!term || `${node.label || ''} ${node.rawId || ''} ${assetKindLabel(node.type)}`.toLocaleLowerCase().includes(term))
  ).sort((a, b) => (order[a.type] ?? 8) - (order[b.type] ?? 8) || String(a.label).localeCompare(String(b.label), 'zh-CN'))
}

export { HOST_TYPES }
