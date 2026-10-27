import cytoscape from 'cytoscape'
import svg from 'cytoscape-svg'
import { projectElements } from './executionCanvasModel.js'

cytoscape.use(svg)

/** @typedef {{ id: string, type: string, title?: string, summary?: string, verification_status?: string, evidence_ids?: string[] }} BlackboardItem */
/** @typedef {{ id: string, raw_id?: string, type: string, status?: string, title?: string, label?: string, description?: string, worker?: string, current_tool?: string, items?: BlackboardItem[] }} BlackboardNode */
/** @typedef {{ id: string, source: string, target: string, label?: string, relation?: string, type?: string, status?: string }} BlackboardEdge */
/** @typedef {{ nodes: BlackboardNode[], edges: BlackboardEdge[] }} BlackboardSnapshot */
/** @typedef {import('cytoscape').Core & { svg: (options: { full: boolean, scale: number, bg: string }) => string }} SvgGraph */

/**
 * Render a detached, fully expanded projection without changing the live canvas.
 * @param {BlackboardSnapshot} graph
 * @param {HTMLElement} view
 * @returns {string}
 */
export function createBlackboardSvg(graph, view) {
  const projected = structuredClone(projectElements(graph, new Set(graph.nodes.map((node) => node.id)), '', true))
  const elements = projected.map((element) => {
    if (element.group !== 'nodes') return element
    const node = element.data
    const display = [node.display.split('\n')[0], node.title || node.label || node.description || '未命名记录',
      `ID: ${node.id}`, node.worker, node.current_tool].filter(Boolean).join('\n')
    return { ...element, data: { ...node, display } }
  })
  if (!elements.some((element) => element.group === 'nodes')) throw new RangeError('黑板没有可导出的节点')
  const palette = getComputedStyle(view)
  /** @param {string} name @returns {string} */
  const color = (name) => {
    const value = palette.getPropertyValue(`--ec-${name}`).trim()
    if (!value) throw new TypeError(`黑板主题缺少颜色变量 --ec-${name}`)
    return value
  }
  /** @type {import('cytoscape').StylesheetJson} */
  const styles = [
    { selector: 'node', style: { shape: 'round-rectangle', width: 320, height: 'label', padding: 20,
      'background-color': color('panel'), 'background-opacity': 1, 'border-width': 1, 'border-color': color('border'),
      label: 'data(display)', color: color('text'), 'font-family': 'Microsoft YaHei, Segoe UI, sans-serif', 'font-size': 12,
      'text-wrap': 'wrap', 'text-overflow-wrap': 'anywhere', 'text-max-width': 280, 'text-valign': 'center', 'text-halign': 'center', 'line-height': 1.4, 'overlay-opacity': 0 } },
    { selector: 'node.kind-intent, node.state-running, node.state-exploring', style: { 'border-color': color('blue') } },
    { selector: 'node.kind-fact', style: { 'border-color': color('purple') } },
    { selector: 'node.kind-goal, node.kind-item', style: { 'border-color': color('green') } },
    { selector: 'node.kind-digest, node.state-approval', style: { 'border-color': color('amber') } },
    { selector: 'node.state-failed, node.state-timeout', style: { 'border-color': color('red') } },
    { selector: 'edge', style: { width: 1.6, 'line-color': color('edge'), 'target-arrow-color': color('edge'), 'target-arrow-shape': 'triangle',
      'curve-style': 'taxi', 'taxi-direction': 'horizontal', 'taxi-turn-min-distance': 25, 'overlay-opacity': 0,
      label: (edge) => edge.data('label') || edge.data('relation') || edge.data('type') || '', 'font-size': 10,
      'font-family': 'Microsoft YaHei, Segoe UI, sans-serif', color: color('muted'), 'text-background-color': color('soft'),
      'text-background-opacity': 1, 'text-background-padding': 3 } },
    { selector: 'edge.edge-running', style: { 'line-style': 'dashed', 'line-color': color('blue'), 'target-arrow-color': color('blue') } },
    { selector: 'edge.edge-approval', style: { 'line-style': 'dashed', 'line-color': color('amber'), 'target-arrow-color': color('amber') } },
    { selector: 'edge.edge-contains', style: { 'line-style': 'dotted' } },
  ]
  const container = document.createElement('div')
  container.setAttribute('aria-hidden', 'true')
  container.style.cssText = 'position:fixed;left:-10000px;top:0;width:1200px;height:800px;pointer-events:none;opacity:0;'
  /** @type {SvgGraph | null} */
  let cy = null
  try {
    document.body.appendChild(container)
    cy = /** @type {SvgGraph} */ (cytoscape({ container, elements, style: styles, pixelRatio: 1,
      layout: { name: 'preset' }, userPanningEnabled: false, userZoomingEnabled: false }))
    cy.layout({ name: 'dagre', rankDir: 'LR', nodeSep: 66, rankSep: 90, edgeSep: 24, fit: false, animate: false }).run()
    const content = cy.svg({ full: true, scale: 1, bg: color('soft') })
    const documentSvg = new DOMParser().parseFromString(content, 'image/svg+xml')
    if (documentSvg.querySelector('parsererror')) throw new SyntaxError('SVG 渲染器输出了无效 XML')
    if (documentSvg.querySelector('image, foreignObject')) throw new TypeError('SVG 渲染器输出了非矢量内容')
    const root = documentSvg.documentElement
    const width = Number(root.getAttribute('width'))
    const height = Number(root.getAttribute('height'))
    if (!(width > 0 && height > 0)) throw new RangeError(`SVG 尺寸无效：${width} × ${height}`)
    root.setAttribute('viewBox', `-24 -24 ${width + 48} ${height + 48}`)
    root.setAttribute('width', String(width + 48))
    root.setAttribute('height', String(height + 48))
    return new XMLSerializer().serializeToString(documentSvg)
  } finally {
    try { cy?.destroy() } finally { container.remove() }
  }
}

/** @param {string} content @param {string} runId @returns {void} */
export function downloadBlackboardSvg(content, runId) {
  const link = document.createElement('a')
  const url = URL.createObjectURL(new Blob([content], { type: 'image/svg+xml;charset=utf-8' }))
  try {
    link.href = url
    link.download = `secmind-blackboard-${runId.replace(/[^a-zA-Z0-9_-]/g, '_')}.svg`
    document.body.appendChild(link)
    link.click()
  } finally {
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}
