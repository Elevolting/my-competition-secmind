import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { App, Button, Empty, Input, Modal, Segmented, Tooltip } from 'antd'
import { BulbOutlined, ReloadOutlined, SearchOutlined, ApartmentOutlined } from '@ant-design/icons'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { getBlackboardGraph, submitRunHint } from '../api.js'
import './ExecutionCanvas.css'
import ExecutionNodeCard, { StatusBadge } from './ExecutionNodeCard.jsx'
import ExecutionDetails from './ExecutionDetails.jsx'
import TraceSearch from './TraceSearch.jsx'

cytoscape.use(dagre)

import { STATUS, TERMINAL, ACTIVE, executionElapsed, isExecutionFinished, isIntent, projectElements } from './executionCanvasModel.js'
const empty = { nodes: [], edges: [], linked: false }
const short = (value, max = 70) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, max)

const style = [
  { selector: 'node', style: { shape: 'round-rectangle', width: 206, height: 136, 'background-color': '#11161a', 'border-width': 0, 'background-opacity': 0,
    'border-color': '#5a6972', label: '', color: '#e7eff1', 'font-size': 12, 'font-family': 'Microsoft YaHei, sans-serif',
    'text-wrap': 'wrap', 'text-max-width': 210, 'text-valign': 'center', 'text-halign': 'center', 'line-height': 1.35, 'overlay-opacity': 0 } },
  { selector: 'node.kind-intent', style: { width: 224, height: 136, 'background-color': '#11161a', 'border-color': '#62d9ff' } },
  { selector: 'node.kind-origin', style: { 'border-color': '#8ea3ab' } },
  { selector: 'node.kind-goal', style: { 'border-color': '#6abd98' } },
  { selector: 'node.kind-fact', style: { height: 136, 'background-color': '#11161a', 'border-color': '#9aaec4' } },
  { selector: 'node.kind-item', style: { width: 206, height: 136, 'border-color': '#9aaec4' } },
  { selector: 'node.state-failed, node.state-timeout', style: { 'border-color': '#d46a70' } },
  { selector: 'node.state-approval', style: { 'border-color': '#e0b25c' } },
  { selector: 'edge.is-dim', style: { opacity: 0.23 } },
  { selector: 'edge', style: { width: 1.6, 'line-color': '#607681', 'target-arrow-color': '#607681', 'target-arrow-shape': 'triangle',
    'curve-style': 'taxi', 'taxi-direction': 'horizontal', 'taxi-turn-min-distance': 25, 'overlay-opacity': 0, label: 'data(label)', 'font-size': 10, color: '#81959d', 'text-background-color': '#10191e', 'text-background-opacity': 0.8, 'text-background-padding': 3 } },
  { selector: 'edge.edge-running', style: { 'line-style': 'dashed', 'line-color': '#62d9ff', 'target-arrow-color': '#62d9ff' } },
  { selector: 'edge.edge-approval', style: { 'line-style': 'dashed', 'line-color': '#c29952', 'target-arrow-color': '#c29952' } },
  { selector: 'edge.edge-contains', style: { 'line-style': 'dotted' } },
  { selector: 'edge.is-lineage', style: { width: 2, 'line-color': '#62d9ff', 'target-arrow-color': '#62d9ff' } },
]

function placeNewNodes(cy, incoming) {
  const occupied = cy.nodes().map((node) => ({ ...node.position(), id: node.id() }))
  for (const node of incoming) {
    const predecessors = node.incomers('node')
    const parent = predecessors.length ? predecessors[0].position() : { x: 0, y: occupied.length * 150 }
    let x = parent.x + 370
    let y = parent.y
    while (occupied.some((position) => Math.abs(position.x - x) < 280 && Math.abs(position.y - y) < 185)) y += 210
    node.position({ x, y })
    occupied.push({ id: node.id(), x, y })
  }
}

function detailValue(node, graph) {
  if (!node) return null
  const sources = (node.source_ids || []).map((id) => graph.nodes?.find((item) => item.raw_id === id)?.title || id)
  const parentId = node.parent_fact_id ? graph.nodes?.find((item) => item.raw_id === node.parent_fact_id)?.id || `fact:${node.parent_fact_id}` : node.id
  const producers = (graph.edges || []).filter((edge) => edge.target === parentId && edge.source.startsWith('intent:')).map((edge) => graph.nodes?.find((item) => item.id === edge.source)).filter(Boolean)
  return { ...node, sources, producers }
}

export function BlackboardGraph({ run, events = [] }) {
  const { message } = App.useApp()
  const canvasRef = useRef(null)
  const cardsRef = useRef(new Map())
  const cardLayerRef = useRef(null)
  const zoomLabelRef = useRef(null)
  const cyRef = useRef(null)
  const requestRef = useRef(0)
  const dataRef = useRef(null)
  const selectedRef = useRef(null)
  const followRef = useRef(true)
  const projectRef = useRef(null)
  const animationRef = useRef(null)
  const inflightRef = useRef(null)
  const motionRef = useRef(false)
  const [hidden, setHidden] = useState(document.hidden)
  const [clock, setClock] = useState(Date.now())
  const [graph, setGraph] = useState(null)
  const [selected, setSelected] = useState(null)
  const [detailMode, setDetailMode] = useState('node')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState(new Set())
  const [history, setHistory] = useState(false)
  const [mobileView, setMobileView] = useState('list')
  const [follow, setFollow] = useState(true)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [syncedAt, setSyncedAt] = useState('')
  const [reducedMotion, setReducedMotion] = useState(() => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches || false)
  const [light, setLight] = useState(() => document.body.classList.contains('light-theme'))
  motionRef.current = reducedMotion
  const lastEvent = useMemo(() => events.filter((event) => /^(blackboard|penetration|exploration|mcp\.call|runtime\.)/.test(event.event_type || '')).at(-1)?.sequence, [events])

  const refresh = useCallback(async (quiet = false) => {
    if (!run?.run_id) return
    if (inflightRef.current?.runId === run.run_id) {
      inflightRef.current.pending = true
      if (!quiet) setRefreshing(true)
      return inflightRef.current.promise
    }
    const serial = ++requestRef.current
    const controller = new AbortController()
    const request = { runId: run.run_id, controller, pending: false, promise: null }
    inflightRef.current = request
    if (!quiet) setRefreshing(true)
    request.promise = (async () => {
      try {
        const next = await getBlackboardGraph(run.run_id, AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]))
        if (serial === requestRef.current) {
          const fingerprint = JSON.stringify([next.project_id, next.project?.status, next.nodes, next.edges, next.execution])
          if (dataRef.current !== fingerprint) { dataRef.current = fingerprint; setGraph(next) }
          setError(next.sync_error || '')
          setSyncedAt(new Date().toLocaleTimeString('zh-CN'))
        }
      } catch (cause) {
        if (serial === requestRef.current && !controller.signal.aborted) setError(cause.message || '同步失败')
      } finally {
        if (inflightRef.current === request) inflightRef.current = null
        if (serial === requestRef.current) {
          setRefreshing(false)
          if (request.pending) window.setTimeout(() => { if (serial === requestRef.current) refresh(true) }, 0)
        }
      }
    })()
    return request.promise
  }, [run?.run_id])

  useEffect(() => {
    inflightRef.current?.controller.abort()
    inflightRef.current = null
    requestRef.current += 1
    dataRef.current = null
    projectRef.current = null
    selectedRef.current = null
    setGraph(null); setSelected(null); setExpanded(new Set()); setError(''); setSyncedAt(''); setFollow(true); followRef.current = true
    if (!run?.run_id) return undefined
    refresh()
    const timer = window.setInterval(() => { if (!document.hidden) refresh(true) }, 3000)
    return () => { window.clearInterval(timer); requestRef.current += 1; inflightRef.current?.controller.abort() }
  }, [run?.run_id, refresh])

  useEffect(() => {
    if (!lastEvent) return undefined
    const timer = window.setTimeout(() => refresh(true), 180)
    return () => window.clearTimeout(timer)
  }, [lastEvent, refresh])

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)')
    const narrow = window.matchMedia('(max-width: 850px)')
    const enterNarrow = () => { if (narrow.matches) setMobileView('list') }
    enterNarrow()
    narrow.addEventListener('change', enterNarrow)
    const change = () => setReducedMotion(media.matches)
    media.addEventListener('change', change)
    const observer = new MutationObserver(() => setLight(document.body.classList.contains('light-theme')))
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] })
    return () => { media.removeEventListener('change', change); narrow.removeEventListener('change', enterNarrow); observer.disconnect() }
  }, [])

  const focus = useCallback((id, manual = true) => {
    const cy = cyRef.current
    if (!cy) return
    cy.stop()
    const node = cy.getElementById(id)
    if (node.empty()) return
    cy.elements().unselect().removeClass('is-dim is-lineage')
    node.select()
    const ancestry = node.predecessors().union(node)
    cy.elements().not(ancestry).addClass('is-dim')
    ancestry.edges().addClass('is-lineage')
    selectedRef.current = id
    setSelected(id)
    if (manual) { followRef.current = false; setFollow(false) }
    if (motionRef.current) cy.center(node)
    else cy.animate({ center: { eles: node }, duration: 380 })
  }, [])

  useEffect(() => {
    if (!canvasRef.current || cyRef.current || !run?.run_id) return undefined
    const cy = cytoscape({ container: canvasRef.current, elements: [], style, minZoom: 0.15, maxZoom: 2.6, selectionType: 'single' })
    cy.on('tap', 'node', (event) => focus(event.target.id()))
    cy.on('tap', (event) => { if (event.target === cy) { cy.elements().removeClass('is-dim is-lineage').unselect(); setSelected(null); selectedRef.current = null } })
    cy.on('dragfree pan zoom', (event) => { if (event.originalEvent) { cy.stop(); followRef.current = false; setFollow(false) } })
    cyRef.current = cy
    const observer = new ResizeObserver(() => {
      cy.resize()
      if (followRef.current && cy.nodes().length) {
        const current = cy.nodes('.state-running, .state-exploring').first()
        const region = current.length ? current.predecessors().union(current).union(current.outgoers()) : cy.elements()
        cy.fit(region, 45)
        if (cy.zoom() > 1) { cy.zoom(1); cy.center(region) }
      }
    })
    observer.observe(canvasRef.current)
    return () => { observer.disconnect(); cy.destroy(); cyRef.current = null; projectRef.current = null }
  }, [run?.run_id, focus])

  const shown = graph || empty
  const elements = useMemo(() => projectElements(shown, expanded, query, history), [shown, expanded, query, history])
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const changed = projectRef.current !== shown.project_id
    const oldPositions = new Map(cy.nodes().map((node) => [node.id(), node.position()]))
    const oldIds = new Set(cy.nodes().map((node) => node.id()))
    const nextIds = new Set(elements.map((item) => item.data.id))
    cy.batch(() => {
      cy.elements().filter((item) => !nextIds.has(item.id())).remove()
      for (const element of elements) {
        const current = cy.getElementById(element.data.id)
        if (current.empty()) cy.add(element)
        else {
          if (element.group === "edges" && (current.data("source") !== element.data.source || current.data("target") !== element.data.target)) { current.remove(); cy.add(element) }
          else { current.data(element.data); current.classes(element.classes) }
        }
      }
    })
    if (changed && cy.nodes().length) {
      cy.layout({ name: 'dagre', rankDir: 'LR', nodeSep: 66, rankSep: 50, edgeSep: 24, fit: false, animate: false }).run()
      const current = cy.nodes('.state-running, .state-exploring').first()
      const region = current.length ? current.predecessors().union(current).union(current.outgoers()) : cy.elements()
      cy.fit(region, 45)
      if (cy.zoom() > 1) { cy.zoom(1); cy.center(region) }
      if (current.length && !selectedRef.current) { selectedRef.current = current.id(); setSelected(current.id()); current.select() }
      projectRef.current = shown.project_id
    } else {
      for (const [id, position] of oldPositions) cy.getElementById(id).position(position)
      const incoming = cy.nodes().filter((node) => !oldIds.has(node.id()))
      placeNewNodes(cy, incoming)
      if (!motionRef.current && !document.hidden) { incoming.style("opacity", 0); incoming.animate({ style: { opacity: 1 }, duration: 500, complete: () => incoming.removeStyle("opacity") }) }
      if (followRef.current && incoming.length && !query) cy.animate({ center: { eles: incoming[0] }, duration: reducedMotion ? 0 : 380 })
    }
    if (selectedRef.current && cy.getElementById(selectedRef.current).empty()) { selectedRef.current = null; setSelected(null) }
    if (selectedRef.current && !cy.getElementById(selectedRef.current).empty()) {
      const node = cy.getElementById(selectedRef.current)
      cy.elements().removeClass('is-dim is-lineage')
      const ancestry = node.predecessors().union(node)
      cy.elements().not(ancestry).addClass('is-dim')
      ancestry.edges().addClass('is-lineage')
    }
  }, [elements, shown.project_id, reducedMotion, query])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return undefined
    const disabled = reducedMotion || error || hidden || !['running', 'pending', 'waiting_approval'].includes(run?.status) || shown.project?.status !== 'active'
    if (animationRef.current) window.clearInterval(animationRef.current)
    cy.nodes().removeStyle('underlay-opacity')
    cy.edges().removeStyle('line-dash-offset')
    if (disabled) { cy.stop(); cy.elements().stop().removeStyle('opacity'); return undefined }
    const started = performance.now()
    animationRef.current = window.setInterval(() => {
      const elapsed = performance.now() - started
      cy.edges('.edge-running').style('line-dash-offset', -(elapsed % 700) / 700 * 18)
    }, 60)
    return () => { window.clearInterval(animationRef.current); animationRef.current = null }
  }, [run?.status, shown.project?.status, error, reducedMotion, hidden, elements])

  useEffect(() => { const stop = () => setHidden(document.hidden); document.addEventListener('visibilitychange', stop); return () => document.removeEventListener('visibilitychange', stop) }, [])
  useEffect(() => {
    const cy = cyRef.current
    const view = canvasRef.current?.closest('.execution-view')
    if (!cy || !view) return
    // Cards and edges read one palette, inherited from the workbench theme.
    const palette = getComputedStyle(view)
    const color = (name) => palette.getPropertyValue(`--ec-${name}`).trim()
    cy.style(style.map((rule) => ({ ...rule, style: {
      ...rule.style,
      ...(rule.selector === 'edge' ? { 'line-color': color('edge'), 'target-arrow-color': color('edge'), color: color('muted'), 'text-background-color': color('soft') } : {}),
      ...(['edge.edge-running', 'edge.is-lineage'].includes(rule.selector) ? { 'line-color': color('blue'), 'target-arrow-color': color('blue') } : {}),
      ...(rule.selector === 'edge.edge-approval' ? { 'line-color': color('amber'), 'target-arrow-color': color('amber') } : {}),
    } })))
  }, [light, run?.run_id])

  // HTML cards use the same rendered coordinates as Cytoscape's edges.
  useEffect(() => {
    const cy = cyRef.current
    const layer = cardLayerRef.current
    if (!cy || !layer) return undefined
    let frame = 0
    const sync = () => {
      frame = 0
      const scale = cy.zoom()
      const pixelRatio = window.devicePixelRatio || 1
      const alignPixel = (value) => Math.round(value * pixelRatio) / pixelRatio
      for (const [id, card] of cardsRef.current) {
        const node = cy.getElementById(id)
        if (!node.length) continue
        const position = node.renderedPosition()
        const width = node.width() * scale
        const height = node.height() * scale
        card.style.left = `${alignPixel(position.x - width / 2)}px`
        card.style.top = `${alignPixel(position.y - height / 2)}px`
        card.style.width = `${alignPixel(width)}px`
        card.style.height = `${alignPixel(height)}px`
        card.style.setProperty('--ec-node-scale', scale)
        card.style.removeProperty('transform')
        card.style.opacity = node.hasClass('is-dim') ? '0.4' : node.style('opacity')
        card.classList.toggle('selected', node.selected())
      }
      if (zoomLabelRef.current) zoomLabelRef.current.textContent = `${Math.round(scale * 100)}%`
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(sync) }
    const wheel = (event) => {
      if (!event.target.closest('.execution-node-card')) return
      event.preventDefault()
      cy.stop(); followRef.current = false; setFollow(false)
      const rect = layer.getBoundingClientRect()
      const delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? rect.height : 1)
      cy.zoom({ level: Math.min(2.6, Math.max(0.15, cy.zoom() * Math.exp(-delta * .0015))), renderedPosition: { x: event.clientX - rect.left, y: event.clientY - rect.top } })
    }
    cy.on('render pan zoom position layoutstop add remove data select unselect', schedule)
    layer.addEventListener('wheel', wheel, { passive: false })
    sync()
    return () => { cancelAnimationFrame(frame); cy.off('render pan zoom position layoutstop add remove data select unselect', schedule); layer.removeEventListener('wheel', wheel) }
  }, [elements, run?.run_id])

  useEffect(() => {
    if (!run?.run_id || isExecutionFinished(run.status, shown.project?.status)) return undefined
    setClock(Date.now())
    const timer = window.setInterval(() => setClock(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [run?.run_id, run?.status, shown.project?.status])
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      const cy = cyRef.current
      if (!cy) return
      cy.resize()
      if (mobileView !== 'graph' || !window.matchMedia('(max-width: 850px)').matches) return
      cy.stop()
      const selectedNode = cy.getElementById(selectedRef.current || '')
      const activeNode = cy.nodes('.state-running, .state-exploring').first()
      const region = selectedNode.length ? selectedNode : activeNode.length ? activeNode.closedNeighborhood() : cy.elements()
      if (region.length) { cy.fit(region, 35); if (cy.zoom() > 1) { cy.zoom(1); cy.center(region) } }
    })
    return () => cancelAnimationFrame(frame)
  }, [mobileView])
  const pauseFollow = () => { cyRef.current?.stop(); followRef.current = false; setFollow(false) }
  const elapsed = (node) => executionElapsed(node, clock, run?.status, shown.project?.status)
  const intents = useMemo(() => (shown.nodes || []).filter(isIntent), [shown])
  const active = intents.filter((node) => !TERMINAL.has(node.status))
  const complete = intents.filter((node) => TERMINAL.has(node.status))
  const sorted = [...active].sort((a, b) => ({ running: 0, exploring: 0, approval: 1, failed: 2, timeout: 2, waiting: 3 }[a.status] ?? 4) - ({ running: 0, exploring: 0, approval: 1, failed: 2, timeout: 2, waiting: 3 }[b.status] ?? 4))
  const matchesQueue = (node) => !query || [node.title, node.description, node.worker, node.tool_name, node.raw_id, node.step_id, ...(node.blocked_reasons || []), ...(shown.edges || []).filter((edge) => edge.source === node.id).flatMap((edge) => { const result = shown.nodes.find((item) => item.id === edge.target); return (result?.items || []).map((item) => `${item.title} ${item.summary} ${(item.evidence_ids || []).join(' ')}`) })].join(' ').toLocaleLowerCase().includes(query.toLocaleLowerCase())
  const selectedNode = detailValue((shown.nodes || []).find((node) => node.id === selected) || elements.find((item) => item.data.id === selected)?.data, shown)
  const selectFromList = (id) => { if (window.matchMedia('(max-width: 850px)').matches) setMobileView('graph'); requestAnimationFrame(() => focus(id)) }
  const toggleBundle = (id) => setExpanded((current) => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next })
  const zoom = (factor) => { pauseFollow(); const cy = cyRef.current; if (cy) cy.zoom({ level: Math.min(2.6, Math.max(0.15, cy.zoom() * factor)), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }) }
  const submitHint = () => { let value = ''; Modal.confirm({ title: '向任务提交提示', content: <Input.TextArea rows={4} onChange={(event) => { value = event.target.value }} />, okText: '提交', cancelText: '取消', onOk: async () => { if (!value.trim()) { message.warning('请输入提示内容'); throw new Error('empty') } await submitRunHint(run.run_id, { content: value.trim(), creator: 'web-operator' }); await refresh() } }) }

  const running = sorted.filter((node) => ACTIVE.has(node.status))
  const waiting = sorted.filter((node) => !ACTIVE.has(node.status))
  const resultItems = shown.result_items?.length ? shown.result_items : (shown.nodes || []).flatMap((node) => node.items || [])
  const findings = resultItems.filter((item) => item.type === 'finding')
  const confirmed = findings.filter((item) => item.verification_status === 'confirmed').length
  const motionEnabled = !reducedMotion && !error && !hidden && ['running', 'pending', 'waiting_approval'].includes(run?.status) && shown.project?.status === 'active'
  const queueRow = (node, historical = false) => <button key={node.id} className={`execution-list-item ${historical ? 'history' : ''} ${selected === node.id ? 'selected' : ''}`} onClick={() => selectFromList(node.id)}>
    <span className="execution-row-top"><code>{node.step_id || node.raw_id}</code><StatusBadge status={node.status} /></span>
    <strong>{short(node.title || node.label, 85)}</strong>
    <span className="execution-row-meta"><span>{node.worker || '未领取'}</span><time>{elapsed(node)}</time></span>
    {!!node.blocked_reasons?.length && <small className="execution-queue-activity">{node.blocked_reasons.join('；')}</small>}
    {!historical && <span className={`execution-row-action ${ACTIVE.has(node.status) ? 'is-live' : ''}`}><i />{node.current_tool || (ACTIVE.has(node.status) ? '执行中，暂无工具记录' : node.phase || STATUS[node.status])}</span>}
    <small className="execution-queue-activity" title={node.latest_activity || '未记录最近活动'}>{node.phase || '未记录阶段'} · {node.latest_activity ? new Date(node.latest_activity).toLocaleTimeString('zh-CN') : '暂无活动记录'}</small>
  </button>
  if (!run) return <div className="execution-empty"><Empty description="选择任务后查看执行画布" /></div>
  return <div className={`execution-view ${light ? 'is-light' : ''} ${motionEnabled ? 'motion-enabled' : ''}`}>
    {error && <div className="execution-error" role="alert">{error} · 保留上次同步结果 <Button size="small" onClick={() => refresh()}>重试</Button></div>}
    <div className="execution-overview">
      <div className="execution-metric active-metric"><small>正在执行的想法</small><b>{running.length}<em>条分支</em></b></div>
      <div className="execution-metric"><small>等待审批</small><b>{intents.filter((node) => node.status === 'approval').length}<em>条分支</em></b></div>
      <div className="execution-metric"><small>已记录事实</small><b>{resultItems.length ? resultItems.filter((item) => item.type !== 'finding').length : shown.nodes.filter((node) => node.type === 'fact').length}<em>条事实</em></b></div>
      <div className="execution-metric"><small>漏洞验证</small><b>{confirmed}<em>已确认 / {findings.filter((item) => ['candidate', 'pending', 'insufficient'].includes(item.verification_status)).length} 候选</em></b></div>
    </div>
    <nav className="execution-mobile-tabs" aria-label="画布视图">{[['list', '清单'], ['graph', '画布'], ['detail', '详情']].map(([id, label]) => <button key={id} className={mobileView === id ? 'active' : ''} onClick={() => setMobileView(id)}>{label}</button>)}</nav>
    <div className="execution-columns">
      <aside className={`execution-list execution-mobile-${mobileView}`}><div className="execution-pane-heading"><b>验证想法</b><span>{intents.length} 个想法</span></div>
        <Input prefix={<SearchOutlined />} allowClear placeholder="搜索想法、事实、证据" value={query} onChange={(event) => setQuery(event.target.value)} />
        <div className="execution-list-scroll">
          <div className="execution-section-label"><span>当前执行</span><span>{running.length.toString().padStart(2, '0')}</span></div>
          {running.filter(matchesQueue).map((node) => queueRow(node))}
          <div className="execution-section-label"><span>等待处理</span><span>{waiting.length.toString().padStart(2, '0')}</span></div>
          {waiting.filter(matchesQueue).map((node) => queueRow(node))}
          <div className="execution-section-label"><span>已完成 · {complete.length}</span><button className="execution-history-toggle" aria-expanded={history} onClick={() => setHistory(!history)}>{history ? '收起 ▴' : '展开 ▾'}</button></div>
          {history && complete.filter(matchesQueue).map((node) => queueRow(node, true))}
          {!intents.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无验证想法" />}
          <p className="execution-queue-footer">选择一个想法，即可追溯它的依据、当前动作与产出。</p>
        </div>
      </aside>
      <section className={`execution-graph execution-mobile-${mobileView}`} aria-label="执行画布">
        <header className="execution-canvas-header"><div><b>执行分支</b><small>{selectedNode ? '当前验证路径' : '正在发生的验证'}</small></div><div className="execution-canvas-actions">
          <button aria-label="跟随执行" className={follow ? 'is-active' : ''} onClick={() => { followRef.current = true; setFollow(true); const current = cyRef.current?.nodes('.state-running, .state-exploring').first(); if (current?.nonempty()) cyRef.current.animate({ center: { eles: current }, duration: reducedMotion ? 0 : 380 }) }}>● 跟随执行</button>
          <button aria-label="查看全图" onClick={() => { pauseFollow(); setHistory(true); requestAnimationFrame(() => requestAnimationFrame(() => cyRef.current?.fit(cyRef.current.elements(), 50))) }}>查看全图</button>
        </div></header>
        <div className="execution-viewport">
          <div ref={canvasRef} className="execution-cytoscape" data-testid="penetration-blackboard-canvas" />
          <div ref={cardLayerRef} className="execution-card-layer">{elements.filter((item) => item.group === 'nodes').map((item) => <ExecutionNodeCard key={item.data.id} node={item.data} cyRef={cyRef} focus={focus} pauseFollow={pauseFollow} register={(card) => { if (card) cardsRef.current.set(item.data.id, card); else cardsRef.current.delete(item.data.id) }} />)}</div>
          {!shown.nodes?.length && <div className="execution-canvas-empty"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={refreshing ? '正在读取黑板' : '黑板暂无节点'} /></div>}
          <div className="execution-canvas-tip">单击查看依据 · 拖动平移 · 滚轮缩放</div>
          <div className="execution-zoom-controls"><button aria-label="缩小画布" onClick={() => zoom(.82)}>−</button><span ref={zoomLabelRef}>100%</span><button aria-label="放大画布" onClick={() => zoom(1.22)}>＋</button><Tooltip title="重新整理"><button aria-label="重新整理" onClick={() => { pauseFollow(); cyRef.current?.layout({ name: 'dagre', rankDir: 'LR', nodeSep: 66, rankSep: 50, fit: false, animate: !reducedMotion, animationDuration: 380 }).run() }}><ApartmentOutlined /></button></Tooltip></div>
        </div>
        <footer className="execution-canvas-footer"><div className="execution-legend"><span><i />已记录</span><span><i className="live" />执行中</span><span><i className="wait" />待审批</span></div><span className="execution-sync">{error ? '同步异常' : `最近同步 ${syncedAt || '等待中'}`}</span></footer>
      </section>
      <aside className={`execution-detail execution-mobile-${mobileView}`} aria-label="节点详情">
        <Segmented block size="small" aria-label="详情视图" options={[{ label: '节点详情', value: 'node' }, { label: '执行检索', value: 'traces' }]} value={detailMode} onChange={setDetailMode} />
        {detailMode === 'traces'
          ? <TraceSearch runId={run.run_id} graph={shown} focus={focus} />
          : <ExecutionDetails node={selectedNode} graph={shown} expanded={expanded} toggleBundle={toggleBundle} focus={focus} elapsed={elapsed} />}
      </aside>
    </div>
    <footer className="execution-footer"><span>事实提供依据，想法组织验证，证据支撑结论。</span><span>{shown.nodes?.length || 0} 节点 · {shown.project_id || '未关联项目'} · {resultItems.length} 条结果</span><div>
      <Tooltip title="提交提示"><Button size="small" aria-label="提交提示" icon={<BulbOutlined />} disabled={!shown.linked || !['running', 'pending', 'waiting_approval'].includes(run.status)} onClick={submitHint}>添加提示</Button></Tooltip>
      <Tooltip title="同步"><Button size="small" aria-label="同步画布" icon={<ReloadOutlined />} loading={refreshing} onClick={() => refresh()} /></Tooltip>
    </div></footer>
  </div>
}
