import React from 'react'
import { Tag } from 'antd'
import { projectModuleFlow } from './moduleFlowModel.js'
import { routeFor } from './runStatus.js'

const labels = { code_audit: '代码审计', reverse: '逆向分析', log_analysis: '日志分析', penetration: '渗透测试', unknown: '待识别' }

export function ModuleFlow({ run, events = [] }) {
  const route = routeFor(run)
  const nodes = projectModuleFlow(run, events)
  return <div className="module-flow">
    <div className="module-flow-head"><span>模块流程</span><Tag color={route === 'unknown' ? 'default' : 'cyan'}>{labels[route] || route}</Tag>{Boolean(run?.routing?.confidence) && <small>置信度 {(run.routing.confidence * 100).toFixed(0)}%</small>}</div>
    <div className="module-flow-track">{nodes.map((node, index) => <React.Fragment key={node.label}>
      <div className={`module-flow-node ${node.complete || node.active ? 'is-active' : ''}`} title={node.detail}>
        <b>{node.label}</b><small>{node.complete ? '已确认' : node.active ? '执行中' : '待确认'} · {node.detail}</small>
      </div>{index < nodes.length - 1 && <span className="module-flow-arrow">→</span>}
    </React.Fragment>)}</div>
  </div>
}
