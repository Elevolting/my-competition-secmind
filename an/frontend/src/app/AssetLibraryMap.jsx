import React, { useEffect, useMemo, useRef, useState } from 'react'
import { ApiOutlined, AppstoreOutlined, ClusterOutlined, ExpandOutlined, FolderOpenOutlined, GlobalOutlined, HddOutlined, MinusOutlined, PlusOutlined } from '@ant-design/icons'
import { Link } from 'react-router-dom'
import cytoscape from 'cytoscape'
import { assetIndex, assetKindLabel, assetMapPositions, assetShortName, focusRoot, projectAssetView } from './asset-graph-view.js'
import './AssetCoverageGraph.css'

const ICON = { domain: GlobalOutlined, ip: ClusterOutlined, service: HddOutlined, endpoint: ApiOutlined, bundle: FolderOpenOutlined }
const STATUS = { scoped: '范围已登记', referenced: '发现引用', invoked: '已调用', discovered: '成功观测' }
const TYPES = ['domain', 'ip', 'service', 'endpoint']
const SIZE = 48

function Icon({ type }) {
  const Component = ICON[type] || GlobalOutlined
  return <Component aria-hidden="true" />
}

export function AssetLibraryMap({ graph, busy, onOpen }) {
  const canvasRef = useRef(null), layerRef = useRef(null), cyRef = useRef(null)
  const cardsRef = useRef(new Map()), dragRef = useRef(null)
  const shapeRef = useRef(''), rootRef = useRef(null)
  const [selectedId, setSelectedId] = useState(null)
  const [expanded, setExpanded] = useState([])
  const [query, setQuery] = useState('')
  const [mobileTab, setMobileTab] = useState('map')
  const [zoomPercent, setZoomPercent] = useState(100)
  const index = useMemo(() => assetIndex(graph), [graph])
  const selected = index.nodes.get(selectedId)
  const root = focusRoot(index, selectedId)
  const view = useMemo(() => projectAssetView(graph, root, expanded, selectedId), [graph, root, expanded, selectedId])
  const directory = useMemo(() => (graph?.nodes || []).filter(node =>
    `${node.label} ${assetKindLabel(node.type)}`.toLocaleLowerCase().includes(query.toLocaleLowerCase())), [graph, query])
  const visibleKinds = TYPES.filter(type => view.nodes.some(node => node.type === type))
  const visibleStatuses = ['scoped', 'referenced', 'invoked', 'discovered', 'grouped'].filter(status => view.nodes.some(node => node.status === status))

  useEffect(() => {
    if (selectedId && index.nodes.has(selectedId)) return
    setSelectedId(graph?.nodes?.[0]?.id || null)
  }, [graph, index, selectedId])

  useEffect(() => {
    const cy = cytoscape({ container: canvasRef.current, elements: [], minZoom: .05, maxZoom: 2.2,
      style: [
        { selector: 'node', style: { width: SIZE, height: SIZE, 'background-opacity': 0, 'border-width': 0, label: '' } },
        { selector: 'edge', style: { width: 1.3, 'curve-style': 'straight', 'line-color': '#708592', 'target-arrow-color': '#708592', 'target-arrow-shape': 'triangle', 'arrow-scale': .6, opacity: .8 } },
      ] })
    cyRef.current = cy
    const observer = new ResizeObserver(() => {
      cy.resize()
      if (cy.nodes().length) { cy.fit(cy.elements(), 60); if (cy.zoom() > 1) cy.zoom(1) }
    })
    observer.observe(canvasRef.current)
    return () => { observer.disconnect(); cy.destroy(); cyRef.current = null }
  }, [])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const signature = JSON.stringify([view.nodes.map(node => node.id), view.edges.map(edge => edge.id)])
    const changed = signature !== shapeRef.current || rootRef.current !== view.root
    const sameRoot = rootRef.current === view.root
    const previous = new Map(cy.nodes().map(node => [node.id(), node.position()]))
    cy.elements().remove()
    cy.add(view.nodes.map(node => ({ group: 'nodes', data: node })))
    cy.add(view.edges.map(edge => ({ group: 'edges', data: edge })))
    if (view.nodes.length) {
      const positions = assetMapPositions(view.nodes, view.edges, view.root, sameRoot ? previous : new Map())
      cy.batch(() => { for (const [id, point] of positions) cy.getElementById(id).position(point) })
      if (changed) requestAnimationFrame(() => { if (cyRef.current === cy) { cy.resize(); cy.fit(cy.elements(), 72); if (cy.zoom() > 1) cy.zoom(1) } })
    }
    shapeRef.current = signature; rootRef.current = view.root
  }, [view])

  useEffect(() => {
    if (mobileTab !== 'map') return
    const frame = requestAnimationFrame(() => {
      const cy = cyRef.current
      if (cy?.nodes().length) { cy.resize(); cy.fit(cy.elements(), 60); if (cy.zoom() > 1) cy.zoom(1) }
    })
    return () => cancelAnimationFrame(frame)
  }, [mobileTab])

  useEffect(() => {
    const cy = cyRef.current, layer = layerRef.current
    if (!cy || !layer) return
    let frame = 0
    const sync = () => {
      frame = 0
      const scale = cy.zoom()
      setZoomPercent(Math.round(scale * 100))
      const labelScale = Math.min(3, Math.max(1, .85 / scale))
      const labelWidth = Math.min(156, Math.max(42, 190 * scale) / (scale * labelScale))
      for (const [id, card] of cardsRef.current) {
        const node = cy.getElementById(id)
        if (!node.length) continue
        const point = node.renderedPosition()
        card.style.transform = `translate(${point.x - SIZE * scale / 2}px,${point.y - SIZE * scale / 2}px) scale(${scale})`
        card.style.setProperty('--ar-label-scale', labelScale)
        card.style.setProperty('--ar-label-width', `${labelWidth}px`)
      }
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(sync) }
    const wheel = event => {
      if (!event.target.closest('.ar-node-card')) return
      event.preventDefault()
      const box = layer.getBoundingClientRect()
      cy.zoom({ level: Math.max(.05, Math.min(2.2, cy.zoom() * Math.exp(-event.deltaY * .0015))), renderedPosition: { x: event.clientX - box.left, y: event.clientY - box.top } })
    }
    cy.on('render pan zoom position', schedule)
    layer.addEventListener('wheel', wheel, { passive: false })
    schedule()
    return () => { cancelAnimationFrame(frame); cy.off('render pan zoom position', schedule); layer.removeEventListener('wheel', wheel) }
  }, [view])

  useEffect(() => {
    const move = event => {
      const drag = dragRef.current, cy = cyRef.current
      if (!drag?.active || !cy || event.pointerId !== drag.pointerId) return
      const dx = event.clientX - drag.x, dy = event.clientY - drag.y
      if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true
      if (drag.moved) cy.getElementById(drag.id).position({ x: drag.position.x + dx / cy.zoom(), y: drag.position.y + dy / cy.zoom() })
    }
    const end = event => { if (dragRef.current?.pointerId === event.pointerId) dragRef.current.active = false }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', end)
    window.addEventListener('pointercancel', end)
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', end); window.removeEventListener('pointercancel', end) }
  }, [])

  const choose = id => { setSelectedId(id); if (window.matchMedia('(max-width:780px)').matches) setMobileTab('detail') }
  const zoom = factor => { const cy = cyRef.current; if (cy) cy.zoom({ level: Math.max(.05, Math.min(2.2, cy.zoom() * factor)), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }) }
  const openService = node => setExpanded(current => [...new Set([...current, node.parentId])])

  return <div className="asset-reference-view asset-library-map">
    <div className="ar-stage" data-tab={mobileTab}>
      <nav className="ar-mobile-tabs" aria-label="资产地图视图">{[['list', '资产目录'], ['map', '关系图'], ['detail', '详情']].map(([key, label]) => <button key={key} type="button" className={mobileTab === key ? 'active' : ''} onClick={() => setMobileTab(key)}>{label}</button>)}</nav>
      <aside className="ar-directory"><div className="ar-panel-title"><b>资产目录</b><small>{graph?.total || 0} 项</small></div>
        <label className="ar-search"><input aria-label="地图内搜索资产" placeholder="搜索当前结果…" value={query} onChange={event => setQuery(event.target.value)} /></label>
        <div className="ar-directory-scroll">{directory.map(node => <button key={node.id} type="button" title={node.label} className={`ar-asset-row ${selectedId === node.id ? 'selected' : ''}`} onClick={() => choose(node.id)}><span className="ar-asset-icon"><Icon type={node.type} /></span><span className="ar-asset-copy"><strong>{assetShortName(node)}</strong><small>{assetKindLabel(node.type)} · {node.run_count} 个任务</small></span></button>)}{!directory.length && <div className="ar-empty">{busy ? '正在读取资产…' : '没有匹配的资产'}</div>}</div>
      </aside>
      <section className="ar-map" aria-label="跨任务资产地图"><div className="ar-map-head"><div><strong>聚焦 · {assetShortName(index.nodes.get(root)) || '资产关系'}</strong><span>{view.nodes.length} 个可见节点 · {graph?.edges?.length || 0} 条已记录关系</span></div><span className="ar-map-badge">资产地图</span></div>
        <div className="ar-map-body"><div className="ar-map-canvas"><div className="ar-cy" ref={canvasRef} /><div className="ar-card-layer" ref={layerRef}>{view.nodes.map(node => <button key={node.id} ref={element => { if (element) cardsRef.current.set(node.id, element); else cardsRef.current.delete(node.id) }} type="button" data-asset-id={node.id} className={`ar-node-card type-${node.type} status-${node.status} ${selectedId === node.id ? 'selected' : ''}`} title={node.label} aria-label={`${assetKindLabel(node.type)}：${node.label}`} onPointerDown={event => {
          if (event.button !== 0) return
          const element = cyRef.current?.getElementById(node.id)
          if (!element?.length) return
          event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId)
          dragRef.current = { id: node.id, pointerId: event.pointerId, x: event.clientX, y: event.clientY, position: { ...element.position() }, moved: false, active: true }
        }} onClick={() => { if (dragRef.current?.moved) { dragRef.current = null; return } dragRef.current = null; node.type === 'bundle' ? openService(node) : choose(node.id) }}><span className="ar-node-symbol"><Icon type={node.type} /></span><span className="ar-node-label"><strong>{assetShortName(node)}</strong><small>{node.type === 'bundle' ? '展开端点' : STATUS[node.status] || '资产'}</small></span></button>)}</div>
          {!!view.nodes.length && <details className="ar-map-legend" aria-label="资产图例"><summary className="ar-legend-toggle"><AppstoreOutlined />图例</summary><div className="ar-legend-content"><div className="ar-legend-title">颜色代表类型 · 边框代表状态</div><div className="ar-legend-kinds">{visibleKinds.map(type => <span className={`type-${type}`} key={type}><i><Icon type={type} /></i>{assetKindLabel(type)}</span>)}</div><div className="ar-legend-status">{visibleStatuses.map(status => <span key={status}><i className={`status-${status}`} />{STATUS[status] || '已折叠'}</span>)}</div></div></details>}
          {!view.nodes.length && <div className="ar-map-empty">{busy ? '正在读取资产地图…' : '暂无可展示的资产'}</div>}
          <div className="ar-map-actions" role="group" aria-label="地图操作"><button type="button" aria-label="缩小资产图" title="缩小" onClick={() => zoom(.8)}><MinusOutlined /></button><span className="ar-zoom-percent">{zoomPercent}%</span><button type="button" aria-label="放大资产图" title="放大" onClick={() => zoom(1.25)}><PlusOutlined /></button><button type="button" aria-label="适配资产图" title="适配画布" onClick={() => cyRef.current?.fit(cyRef.current.elements(), 72)}><ExpandOutlined /></button></div>
        </div></div><div className="ar-map-foot">连线表示同一任务中已记录的资产归属 · 选择节点查看任务来源</div>
      </section>
      <aside className="ar-detail"><div className="ar-panel-title"><b>资产详情</b><small>{selected?.type?.toUpperCase() || 'ASSET'}</small></div><div className="ar-detail-scroll">{selected ? <><div className="ar-detail-kind"><span><Icon type={selected.type} /></span>{assetKindLabel(selected.type)}</div><h3>{selected.label}</h3><div className="ar-chips"><span>{STATUS[selected.status]}</span><span>{selected.run_count} 个来源任务</span><span>{selected.observed_run_count} 个有成功观测</span></div><section><div className="ar-section-title">来源任务 <small>{selected.runs.length} 项</small></div>{selected.runs.map(run => <div className="ar-evidence" key={run.run_id}><div><b><Link to={`/workbench?run=${encodeURIComponent(run.run_id)}`}>{run.run_id}</Link></b><small>{run.coverage === 'observed' ? '有成功观测' : '无成功观测'} · {STATUS[run.status] || run.status}</small></div></div>)}</section><button type="button" className="ar-open-asset" onClick={() => onOpen(selected.id)}>查看完整来源与证据</button><div className="ar-detail-note">不同任务的授权范围和观测记录分别保存；地图关系不代表完整测试覆盖。</div></> : <div className="ar-detail-placeholder">从目录或画布中选择资产。</div>}</div></aside>
    </div>
  </div>
}
