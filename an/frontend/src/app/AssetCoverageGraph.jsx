import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Empty } from 'antd'
import { ExpandOutlined, MinusOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { getAssetGraph } from '../api.js'
import { assetDirectory, assetIndex, assetKindLabel, assetPath, assetShortName, assetStatusLabel, focusRoot, projectAssetView, relatedCalls } from './asset-graph-view.js'
import './AssetCoverageGraph.css'

cytoscape.use(dagre)
const EMPTY = { nodes: [], edges: [], calls: [], sources: {}, stats: {} }
const ICON = { company: '◈', domain: '◎', subdomain: '⌁', ip: '⌗', service: '▰', app: '▣', endpoint: '↗', artifact: '▤', bundle: '▦' }
const SOURCE = { scope: '任务授权范围', invocation: '工具调用目标', tool: '工具发现记录', artifact: '输入材料' }
const GROUP = { company: '授权目标', domain: '授权目标', subdomain: '授权目标', ip: '授权目标', app: '授权目标', service: '服务与端点', endpoint: '服务与端点', artifact: '输入材料' }
const STYLE = [
  { selector: 'node', style: { width:174, height:76, shape:'round-rectangle', 'background-opacity':0, 'border-width':0, label:'', 'overlay-opacity':0 } },
  { selector: 'edge', style: { width:1.5, 'curve-style':'taxi', 'taxi-direction':'horizontal', 'taxi-turn-min-distance':22, 'line-color':'#55717d', 'target-arrow-color':'#55717d', 'target-arrow-shape':'triangle', 'arrow-scale':.7, opacity:.7, label:'data(label)', 'font-size':9, color:'#829ba4', 'text-background-color':'#101d23', 'text-background-opacity':.95, 'text-background-padding':3, 'overlay-opacity':0 } },
  { selector: 'edge.edge-exposes', style: { 'line-style':'dashed' } },
  { selector: 'edge.is-lineage', style: { width:2.2, 'line-color':'#70d5e7', 'target-arrow-color':'#70d5e7', opacity:1 } },
  { selector: 'edge.is-dim', style: { opacity:.17 } },
]

function timeLabel(value) {
  if (!value) return '时间未记录'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN')
}
function markSelection(cy, id) {
  cy.elements().removeClass('is-dim is-lineage').unselect()
  const node = cy.getElementById(id || '')
  if (!node.length) return
  node.select()
  const upstream = node.predecessors().union(node)
  cy.edges().not(upstream.edges()).addClass('is-dim')
  upstream.edges().addClass('is-lineage')
}
function fitGraph(cy, region = null) {
  if (!cy?.elements().length) return
  const elements = region || cy.elements()
  cy.stop(); cy.resize(); cy.fit(elements, 42)
  if (cy.zoom() > 1) { cy.zoom(1); cy.center(elements) }
}

export function AssetCoverageGraph({ run }) {
  const runId = run?.run_id
  const canvasRef = useRef(null), layerRef = useRef(null), cyRef = useRef(null)
  const cardsRef = useRef(new Map()), selectionHandler = useRef(null), dragRef = useRef(null)
  const requestRef = useRef(0), currentRun = useRef(runId), fingerprintRef = useRef(null)
  const activeRequest = useRef(null)
  const shapeRef = useRef(''), focusRef = useRef(null)
  const [graph, setGraph] = useState(null)
  const [selectedId, setSelectedId] = useState(null), [rootId, setRootId] = useState(null)
  const [expanded, setExpanded] = useState([])
  const [query, setQuery] = useState(''), [filter, setFilter] = useState('all')
  const [mobileTab, setMobileTab] = useState('list')
  const [light, setLight] = useState(() => typeof document !== 'undefined' && document.body.classList.contains('light-theme'))
  const [error, setError] = useState(''), [syncedAt, setSyncedAt] = useState(null), [refreshing, setRefreshing] = useState(false)
  currentRun.current = runId

  const refresh = useCallback(async (quiet = false) => {
    if (!runId) return
    if (activeRequest.current?.runId === runId) return
    const active = { runId, controller:new AbortController() }
    activeRequest.current = active
    const ticket = ++requestRef.current
    if (!quiet) setRefreshing(true)
    try {
      const next = await getAssetGraph(runId, AbortSignal.any([active.controller.signal, AbortSignal.timeout(15000)]))
      if (currentRun.current !== runId || ticket !== requestRef.current) return
      const fingerprint = JSON.stringify(next)
      if (fingerprintRef.current !== fingerprint) { fingerprintRef.current = fingerprint; setGraph(next) }
      setSyncedAt(new Date()); setError('')
    } catch (reason) {
      if (currentRun.current === runId && ticket === requestRef.current) setError(reason?.message || '读取资产引用数据失败')
    } finally {
      if (activeRequest.current === active) activeRequest.current = null
      if (currentRun.current === runId && ticket === requestRef.current) setRefreshing(false)
    }
  }, [runId])

  useEffect(() => {
    activeRequest.current?.controller.abort(); activeRequest.current = null
    requestRef.current += 1; fingerprintRef.current = null; shapeRef.current = ''; focusRef.current = null
    setGraph(null); setSelectedId(null); setRootId(null); setExpanded([]); setQuery(''); setFilter('all'); setError(''); setSyncedAt(null); setRefreshing(false)
    if (!runId) return undefined
    refresh()
    const timer = window.setInterval(() => { if (!document.hidden) refresh(true) }, 5000)
    return () => { window.clearInterval(timer); requestRef.current += 1; activeRequest.current?.controller.abort(); activeRequest.current = null }
  }, [runId, refresh])
  useEffect(() => {
    const observer = new MutationObserver(() => setLight(document.body.classList.contains('light-theme')))
    observer.observe(document.body, { attributes:true, attributeFilter:['class'] })
    return () => observer.disconnect()
  }, [])

  const shown = graph && (!graph.run_id || graph.run_id === runId) ? graph : EMPTY
  const index = useMemo(() => assetIndex(shown), [shown])
  const selected = index.nodes.get(selectedId) || null
  const actualRoot = rootId && index.nodes.has(rootId) ? rootId : focusRoot(index, selectedId)
  const lineageSelection = selectedId === actualRoot ? null : selectedId
  const view = useMemo(() => projectAssetView(shown, actualRoot, expanded, selectedId), [shown, actualRoot, expanded, selectedId])
  const directory = useMemo(() => assetDirectory(shown, query, filter), [shown, query, filter])
  const grouped = useMemo(() => {
    const groups = new Map()
    for (const node of directory) { const key = GROUP[node.type] || '其他资产'; if (!groups.has(key)) groups.set(key, []); groups.get(key).push(node) }
    return [...groups]
  }, [directory])
  const path = useMemo(() => assetPath(index, selectedId), [index, selectedId])
  const calls = useMemo(() => relatedCalls(selected, shown.calls), [selected, shown.calls])
  const provenance = selected?.provenance || []
  const services = view.nodes.filter((node) => node.type === 'service' && (index.children.get(node.id) || []).filter((id) => index.nodes.get(id)?.type === 'endpoint').length > 4)
  const allOpen = services.length > 0 && services.every((node) => expanded.includes(node.id))
  const upstreamIds = useMemo(() => {
    const ids = new Set(selectedId ? [selectedId] : [])
    const queue = [...ids]
    for (let i=0; i<queue.length; i++) for (const id of index.parents.get(queue[i]) || []) if (!ids.has(id)) { ids.add(id); queue.push(id) }
    return ids
  }, [index, selectedId])

  const selectAsset = useCallback((id) => {
    const node = index.nodes.get(id)
    if (!node) return
    setRootId(focusRoot(index, id)); setSelectedId(id)
    if (node.type === 'endpoint') setExpanded((current) => [...new Set([...current, ...(index.parents.get(id) || []).filter((parent) => index.nodes.get(parent)?.type === 'service')])])
    if (window.matchMedia('(max-width:780px)').matches) setMobileTab('detail')
  }, [index])
  selectionHandler.current = selectAsset

  useEffect(() => {
    if (!index.nodes.size || selected) return
    const id = focusRoot(index, null)
    setSelectedId(id); setRootId(id)
  }, [index, selected])

  useEffect(() => {
    if (!canvasRef.current || !runId) return undefined
    const cy = cytoscape({ container:canvasRef.current, elements:[], style:STYLE, minZoom:.2, maxZoom:2.2, selectionType:'single' })
    cyRef.current = cy
    cy.on('tap', 'node', (event) => selectionHandler.current?.(event.target.id()))
    const observer = new ResizeObserver(() => cy.resize())
    observer.observe(canvasRef.current)
    return () => { observer.disconnect(); cy.destroy(); cyRef.current = null }
  }, [runId])
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const palette = getComputedStyle(canvasRef.current.closest('.asset-reference-view'))
    const color = (name) => palette.getPropertyValue(`--ar-${name}`).trim()
    cy.style(STYLE.map((rule) => ({ ...rule, style:{ ...rule.style,
      ...(rule.selector === 'edge' ? { 'line-color':color('edge'), 'target-arrow-color':color('edge'), color:color('muted'), 'text-background-color':color('surface') } : {}),
      ...(rule.selector === 'edge.is-lineage' ? { 'line-color':color('accent'), 'target-arrow-color':color('accent') } : {}),
    } })))
  }, [light, runId])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const signature = JSON.stringify([view.nodes.map((node) => node.id).sort(), view.edges.map((edge) => `${edge.id}:${edge.source}:${edge.target}`).sort()])
    const changedFocus = focusRef.current !== view.root
    const positions = new Map(cy.nodes().map((node) => [node.id(), node.position()]))
    const nextIds = new Set([...view.nodes, ...view.edges].map((item) => item.id))
    cy.batch(() => {
      cy.elements().filter((element) => !nextIds.has(element.id())).remove()
      for (const node of view.nodes) {
        const current = cy.getElementById(node.id)
        if (current.length) current.data(node)
        else cy.add({ group:'nodes', data:node, classes:`type-${node.type}` })
      }
      for (const edge of view.edges) {
        const current = cy.getElementById(edge.id)
        if (current.length && (current.data('source') !== edge.source || current.data('target') !== edge.target)) current.remove()
        const actual = cy.getElementById(edge.id)
        if (actual.length) actual.data(edge)
        else cy.add({ group:'edges', data:edge, classes:`edge-${edge.type}` })
      }
    })
    if (cy.nodes().length && (changedFocus || shapeRef.current !== signature)) {
      cy.layout({ name:'dagre', rankDir:'LR', rankSep:74, nodeSep:36, edgeSep:20, fit:false, animate:false }).run()
      if (!changedFocus && positions.size) {
        cy.batch(() => { for (const [id, position] of positions) cy.getElementById(id).position(position) })
        // Place only incoming cards downstream, avoiding old and new cards.
        let placed = cy.nodes().filter((node) => positions.has(node.id()))
        for (const node of cy.nodes().filter((node) => !positions.has(node.id()))) {
          const parent = node.incomers('node').first()
          const base = parent.length ? { x:parent.position('x') + 248, y:parent.position('y') } : node.position()
          let y = base.y
          while (placed.some((other) => Math.abs(other.position('x') - base.x) < 190 && Math.abs(other.position('y') - y) < 106)) y += 112
          node.position({ x:base.x, y }); placed = placed.merge(node)
        }
      } else fitGraph(cy)
    }
    markSelection(cy, lineageSelection)
    shapeRef.current = signature; focusRef.current = view.root
  }, [view, selectedId, runId])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    markSelection(cy, lineageSelection)
    const node = cy.getElementById(selectedId || '')
    if (node.length && canvasRef.current.offsetWidth) {
      const box = node.renderedBoundingBox()
      if (box.x1 < 12 || box.y1 < 30 || box.x2 > cy.width()-12 || box.y2 > cy.height()-12) { cy.stop(); cy.center(node) }
    }
  }, [selectedId, actualRoot, lineageSelection, runId])

  useEffect(() => {
    const cy = cyRef.current, layer = layerRef.current
    if (!cy || !layer) return undefined
    let frame = 0
    const sync = () => {
      frame = 0
      const scale = cy.zoom()
      for (const [id, card] of cardsRef.current) {
        const node = cy.getElementById(id)
        if (!node.length) continue
        const point = node.renderedPosition()
        card.style.transform = `translate(${point.x - 174 * scale / 2}px,${point.y - 76 * scale / 2}px) scale(${scale})`
      }
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(sync) }
    const wheel = (event) => {
      if (!event.target.closest('.ar-node-card')) return
      event.preventDefault()
      const box = layer.getBoundingClientRect()
      const delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? box.height : 1)
      cy.zoom({ level:Math.max(.2, Math.min(2.2, cy.zoom() * Math.exp(-delta * .0015))), renderedPosition:{ x:event.clientX-box.left, y:event.clientY-box.top } })
    }
    cy.on('render pan zoom position layoutstop add remove', schedule)
    layer.addEventListener('wheel', wheel, { passive:false })
    schedule()
    return () => { cancelAnimationFrame(frame); cy.off('render pan zoom position layoutstop add remove', schedule); layer.removeEventListener('wheel', wheel) }
  }, [view, runId])
  useEffect(() => {
    if (mobileTab !== 'map' || !window.matchMedia('(max-width:780px)').matches) return undefined
    const frame = requestAnimationFrame(() => {
      const cy = cyRef.current
      const node = cy?.getElementById(selectedId || '')
      fitGraph(cy, node?.length ? node.closedNeighborhood() : null)
    })
    return () => cancelAnimationFrame(frame)
  }, [mobileTab, selectedId])

  const zoom = (factor) => {
    const cy = cyRef.current
    if (cy) cy.zoom({ level:Math.max(.2, Math.min(2.2, cy.zoom()*factor)), renderedPosition:{ x:cy.width()/2, y:cy.height()/2 } })
  }
  const cardDown = (event, id) => {
    if (event.button !== 0) return
    const node = cyRef.current?.getElementById(id)
    if (!node?.length) return
    event.currentTarget.setPointerCapture(event.pointerId)
    dragRef.current = { id, x:event.clientX, y:event.clientY, position:{ ...node.position() }, moved:false }
  }
  const cardMove = (event) => {
    const drag = dragRef.current, cy = cyRef.current
    if (!drag || !cy) return
    const dx = event.clientX-drag.x, dy = event.clientY-drag.y
    if (Math.abs(dx)+Math.abs(dy)>4) drag.moved = true
    if (drag.moved) cy.getElementById(drag.id).position({ x:drag.position.x+dx/cy.zoom(), y:drag.position.y+dy/cy.zoom() })
  }
  const cardClick = (node) => {
    if (dragRef.current?.moved) { dragRef.current = null; return }
    dragRef.current = null
    if (node.type === 'bundle') setExpanded((current) => [...new Set([...current, node.parentId])])
    else selectAsset(node.id)
  }
  if (!run) return <div className="blackboard-empty"><Empty description="选择任务后显示资产引用图" /></div>

  return <div className="asset-reference-view">
    <header className="ar-intro"><div><span className="ar-eyebrow">ASSET REFERENCES / {String(runId).slice(0,8)}</span><h2>资产引用图</h2><p>从授权范围、实际调用和工具发现追溯资产关系。</p></div><div className="ar-summary"><span><b>{shown.nodes.length}</b> 资产</span><span><b>{shown.edges.length}</b> 关系</span><span><b>{shown.nodes.filter((node) => node.status === 'discovered').length}</b> 工具发现</span><span className={`ar-sync ${error ? 'is-error' : ''}`}>{error ? '同步异常' : syncedAt ? `已同步 ${syncedAt.toLocaleTimeString('zh-CN')}` : '读取中'}</span></div></header>
    {error && <div className="ar-error" role="alert">资产数据同步异常：{error}。{syncedAt ? '显示上次成功读取的记录。' : '尚未读取到资产记录。'}<button type="button" onClick={() => refresh()}>重试</button></div>}
    <div className="ar-stage" data-tab={mobileTab}>
      <nav className="ar-mobile-tabs" aria-label="资产视图">{[['list','资产目录'],['map','关系图'],['detail','详情']].map(([key,name]) => <button key={key} type="button" className={mobileTab===key ? 'active' : ''} onClick={() => setMobileTab(key)}>{name}</button>)}</nav>
      <aside className="ar-directory"><div className="ar-panel-title"><b>资产目录</b><small>{shown.nodes.length} 项</small></div><label className="ar-search"><SearchOutlined /><input aria-label="搜索资产" placeholder="搜索域名、服务、端点…" value={query} onChange={(event) => setQuery(event.target.value)} /></label><div className="ar-filters" aria-label="资产筛选">{[['all','全部'],['discovered','工具发现'],['invoked','已调用']].map(([key,name]) => <button key={key} type="button" className={filter===key ? 'active' : ''} onClick={() => setFilter(key)}>{name}</button>)}</div><div className="ar-directory-scroll">{grouped.map(([group,nodes]) => <section key={group}><div className="ar-group-title">{group}<span>{nodes.length}</span></div>{nodes.map((node) => <button className={`ar-asset-row ${selectedId===node.id ? 'selected' : ''}`} type="button" key={node.id} title={node.label} onClick={() => selectAsset(node.id)}><span className="ar-asset-icon">{ICON[node.type] || '◇'}</span><span className="ar-asset-copy"><strong>{assetShortName(node)}</strong><small>{assetKindLabel(node.type)} · {assetStatusLabel(node.status)}</small></span></button>)}</section>)}{!directory.length && <div className="ar-empty">{shown.nodes.length ? '未找到匹配资产' : refreshing ? '正在读取资产…' : '暂无资产引用记录'}</div>}</div></aside>
      <section className="ar-map"><div className="ar-map-head"><div><strong>聚焦 · {assetShortName(index.nodes.get(actualRoot)) || '资产关系'}</strong><span>{view.nodes.length} 个可见节点 · {view.hiddenCount ? `${view.hiddenCount} 个端点已折叠` : '当前分支全部展开'}</span></div><div className="ar-map-actions"><button type="button" onClick={() => { setSelectedId(actualRoot); setExpanded(allOpen ? [] : services.map((node) => node.id)) }} disabled={!services.length}>{allOpen ? '收起端点' : '展开端点'}</button><button type="button" aria-label="缩小资产图" onClick={() => zoom(.8)}><MinusOutlined /></button><button type="button" aria-label="放大资产图" onClick={() => zoom(1.25)}><PlusOutlined /></button><button type="button" aria-label="适配资产图" onClick={() => fitGraph(cyRef.current)}><ExpandOutlined /></button><button type="button" aria-label="刷新资产图" onClick={() => refresh()} disabled={refreshing}><ReloadOutlined spin={refreshing} /></button></div></div><div className="ar-map-body"><div className="ar-map-legend"><span><i />授权范围</span><span><i />已调用</span><span><i />工具发现</span></div><div className="ar-cy" ref={canvasRef} data-testid="asset-coverage-canvas" /><div className="ar-card-layer" ref={layerRef}>{view.nodes.map((node) => <button key={node.id} ref={(element) => { if (element) cardsRef.current.set(node.id,element); else cardsRef.current.delete(node.id) }} data-asset-id={node.id} className={`ar-node-card status-${node.status} type-${node.type} ${selectedId===node.id ? 'selected' : ''} ${lineageSelection && !upstreamIds.has(node.id) && node.type !== 'bundle' ? 'is-dim' : ''}`} type="button" title={node.label} onPointerDown={(event) => cardDown(event,node.id)} onPointerMove={cardMove} onPointerCancel={() => { dragRef.current=null }} onClick={() => cardClick(node)}><span className="ar-node-kind">{ICON[node.type] || '◇'} &nbsp;{assetKindLabel(node.type)}</span><strong>{assetShortName(node)}</strong><small>{node.type==='bundle' ? '点击展开端点' : assetStatusLabel(node.status)}</small></button>)}</div>{!view.nodes.length && <div className="ar-map-empty">{refreshing ? '正在读取资产关系…' : '暂无可展示的资产关系'}</div>}</div><div className="ar-map-foot">选择资产可查看来源和证据 · 滚轮缩放，拖动画布</div></section>
      <aside className="ar-detail"><div className="ar-panel-title"><b>资产详情</b><small>{selected?.type?.toUpperCase() || 'ASSET'}</small></div><div className="ar-detail-scroll">{selected ? <><div className="ar-detail-kind"><span>{ICON[selected.type] || '◇'}</span>{assetKindLabel(selected.type)}</div><h3>{selected.label}</h3><p>{selected.description && selected.description !== selected.label ? selected.description : `${assetKindLabel(selected.type)}来自${(selected.sources || []).map((source) => SOURCE[source] || source).join('、') || '已记录来源'}。`}</p><div className="ar-chips"><span>{assetStatusLabel(selected.status)}</span><span>{provenance.length} 条来源记录</span>{selected.confidence!=null && <span>置信度 {Math.round(selected.confidence*100)}%</span>}</div><section><div className="ar-section-title">来源路径 <small>PATH</small></div>{path.map((node) => <button key={node.id} className="ar-trace-row" type="button" onClick={() => selectAsset(node.id)}><i /><span><b>{assetShortName(node)}</b><small>{assetKindLabel(node.type)}</small></span></button>)}{(index.parents.get(selectedId) || []).length>1 && <div className="ar-alternate">其他直接来源：{(index.parents.get(selectedId) || []).slice(1).map((id) => <button type="button" key={id} onClick={() => selectAsset(id)}>{assetShortName(index.nodes.get(id))}</button>)}</div>}</section><section><div className="ar-section-title">来源记录 <small>{provenance.length} 条</small></div>{provenance.length ? provenance.map((item,i) => <div className="ar-evidence" key={`${item.source}:${item.ref}:${i}`}><div><b>{SOURCE[item.source] || item.source}</b><small>{timeLabel(item.observed_at)}</small></div><code>{item.ref || '无引用编号'}</code>{item.confidence!=null && <span>置信度 {Math.round(item.confidence*100)}%</span>}</div>) : <p>暂无来源记录</p>}</section><section><div className="ar-section-title">关联工具调用 <small>{calls.length} 条</small></div>{calls.map((call) => <div className="ar-evidence" key={call.call_id}><div><b>{call.tool || '未知工具'}</b><small>{timeLabel(call.completed_at || call.started_at)}</small></div><p>{call.worker || '未记录 Worker'} · {({completed:'调用完成',failed:'调用失败',running:'执行中'})[call.status] || call.status || '状态未记录'}</p><code>{call.call_id}</code></div>)}{!calls.length && <p>暂无明确关联的工具调用</p>}</section>{selected.sha256 && <section><div className="ar-section-title">文件校验 <small>SHA-256</small></div><div className="ar-evidence"><code>{selected.sha256}</code></div></section>}<div className="ar-detail-note">引用关系表示已记录的来源和调用，不代表完整扫描覆盖率或漏洞结论。</div></> : <div className="ar-detail-placeholder">从左侧目录或画布中选择一个资产，查看来源和调用记录。</div>}</div></aside>
    </div><footer className="ar-footer">记录来源：授权范围 {shown.sources?.scope || 0} · 调用目标 {shown.sources?.invocation || 0} · 工具发现 {shown.sources?.tool || 0} · 输入材料 {shown.sources?.artifact || 0}。调用记录不代表已完成扫描。</footer>
  </div>
}
