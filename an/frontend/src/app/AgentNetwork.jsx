import React from 'react'
import { CheckCircleOutlined, FileSearchOutlined, FileTextOutlined, RadarChartOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { StatusTag } from './StatusTag.jsx'

const icons = { interpreter: <RadarChartOutlined />, planner: <FileSearchOutlined />, analyst: <CheckCircleOutlined />, verifier: <SafetyCertificateOutlined />, reporter: <FileTextOutlined /> }
const positions = { interpreter: [50, 12], planner: [18, 42], analyst: [82, 42], verifier: [70, 78], reporter: [30, 78] }

export function AgentNetwork({ network, eventCount }) {
  return <div className="network-module">
    <div className="agent-constellation">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"><ellipse cx="50" cy="49" rx="43" ry="42" /><path d="M50 18 L18 42 L30 78 L70 78 L82 42 Z" /><path d="M50 18 L70 78 M50 18 L30 78 M18 42 L82 42" /></svg>
      {network.roles.map((role) => { const [x, y] = positions[role.id]; return <div key={role.id} data-agent-id={role.id} data-agent-status={role.status} className={`agent-node is-${role.status} ${network.active === role.id ? 'is-current' : ''}`} style={{ left: `${x}%`, top: `${y}%` }}><span>{icons[role.id]}</span><div><b>{role.shortName}</b><small>{role.status === 'completed' ? '完成' : role.status === 'active' ? '工作中' : role.status === 'failed' ? '失败' : '待命'}</small></div></div> })}
    </div>
    <div className="network-summary"><span>当前智能体<strong data-testid="network-active-agent">{network.roles.find((role) => role.id === network.active)?.name || '等待任务'}</strong></span><span>当前节点<strong data-testid="network-active-node">{network.activeNode || '—'}</strong></span><span>账本事件<strong>{eventCount}</strong></span></div>
    <div className="agent-role-list">{network.roles.map((role) => <div className={`agent-role-row is-${role.status}`} key={role.id}><i>{icons[role.id]}</i><span><b>{role.name}</b><small>{role.activity || role.description}</small></span><StatusTag status={role.status} /></div>)}</div>
  </div>
}
