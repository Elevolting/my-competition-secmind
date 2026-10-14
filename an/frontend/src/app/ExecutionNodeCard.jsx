import React, { useRef } from 'react'
import { ACTIVE, STATUS, isIntent } from './executionCanvasModel.js'

export function StatusBadge({ status }) {
  return <span className={`execution-status status-${status}`}>{STATUS[status] || status || '未记录'}</span>
}

export function nodeKind(node) {
  if (isIntent(node)) return '验证想法'
  if (node.type === 'origin') return '任务起点'
  if (node.type === 'goal') return '任务目标'
  if (node.type === 'item') return node.item_type === 'finding' ? '漏洞验证' : '事实条目'
  return node.items?.length ? '结果包' : '已知事实'
}

export default function ExecutionNodeCard({ node, register, cyRef, focus, pauseFollow }) {
  const gesture = useRef(null)
  const dragged = useRef(false)
  const intent = isIntent(node)
  const count = node.items?.length || 0
  const note = intent ? node.current_tool || (ACTIVE.has(node.status) ? '执行中，暂无工具记录' : node.phase || '查看执行记录')
    : count ? `${count} 条结果 · 点击查看与展开` : node.summary || node.provenance || (node.type === 'origin' ? '任务输入与授权范围' : '查看来源与证据')
  return <button type="button" ref={register} data-node-id={node.id}
    className={`execution-node-card kind-${intent ? 'intent' : node.type} state-${node.status}`}
    aria-label={`${node.title || node.label}，${STATUS[node.status] || node.status}`}
    onClick={() => { if (!dragged.current) focus(node.id); dragged.current = false }}
    onPointerDown={(event) => {
      if (event.button !== 0) return
      const cyNode = cyRef.current?.getElementById(node.id)
      if (!cyNode?.length) return
      gesture.current = { x: event.clientX, y: event.clientY, position: { ...cyNode.position() } }
      dragged.current = false
      event.currentTarget.setPointerCapture(event.pointerId)
    }}
    onPointerMove={(event) => {
      const start = gesture.current
      const cy = cyRef.current
      if (!start || !cy) return
      const dx = event.clientX - start.x, dy = event.clientY - start.y
      if (!dragged.current && Math.hypot(dx, dy) < 4) return
      dragged.current = true
      pauseFollow()
      cy.getElementById(node.id).position({ x: start.position.x + dx / cy.zoom(), y: start.position.y + dy / cy.zoom() })
    }}
    onPointerUp={() => { gesture.current = null }} onPointerCancel={() => { gesture.current = null; dragged.current = false }}>
    <span className="execution-node-kind"><span><i />{nodeKind(node)}</span><code title={node.raw_id}>{node.raw_id}</code></span>
    <strong title={node.title || node.label}>{node.title || node.label || '未命名记录'}</strong>
    <span className={`execution-node-note ${intent && ACTIVE.has(node.status) ? 'is-live' : ''}`} title={note}>{note}</span>
    <span className="execution-node-bottom"><StatusBadge status={node.status} /><small title={intent ? node.worker : node.provenance}>{intent ? node.worker || '未领取' : node.evidence_ids?.length ? `${node.evidence_ids.length} 条证据` : count ? '查看条目 ↗' : node.provenance || '已记录来源'}</small></span>
  </button>
}
