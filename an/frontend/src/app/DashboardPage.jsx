import React, { useEffect, useMemo, useState } from 'react'
import {
  ApartmentOutlined,
  ArrowRightOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  PlusOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { App, Button, Empty, Progress, Tag, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { listModules, listRuns } from '../api.js'
import { compactId } from './runtimeModel.js'
import { StatusTag } from './StatusTag.jsx'
import { classifyRunStatus, externalStatus, isActiveRun, isAttentionRun, isSuccessfulRun, routeFor, summarizeRunStatuses } from './runStatus.js'

const { Text, Title } = Typography
const scenarioLabel = {
  code_audit: '代码审计', reverse_triage: '逆向分析', penetration_test: '渗透测试',
  log_analysis: '日志分析', incident_response: '事件响应', unknown: '识别中',
}

const moduleLabel = { code_audit: '代码审计', audit: '代码审计', reverse: '逆向分析', reverse_triage: '逆向分析', log_analysis: '日志分析', penetration: '渗透测试', penetration_test: '渗透测试', unsupported: '人工研判' }
const externalLabel = {
  submitted: 'Security Runtime 已提交', running: 'Security Runtime 探索中', completed: 'Security Runtime 已完成', complete: 'Security Runtime 已完成',
  succeeded: 'Security Runtime 已完成', success: 'Security Runtime 已完成', failed: 'Security Runtime 失败', timeout: 'Security Runtime 超时',
  unavailable: 'Security Runtime 不可用', poll_error: 'Security Runtime 轮询异常',
}

export function DashboardPage() {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const [runs, setRuns] = useState([])
  const [modules, setModules] = useState([])

  useEffect(() => {
    let alive = true
    const refresh = () => Promise.all([listRuns(), listModules()])
      .then(([runData, moduleData]) => {
        if (!alive) return
        setRuns(runData.runs || [])
        setModules(moduleData.modules || [])
      })
      .catch((error) => message.error(`读取运行态势失败：${error.message}`))
    refresh()
    const timer = window.setInterval(refresh, 6000)
    return () => { alive = false; window.clearInterval(timer) }
  }, [])

  const metrics = useMemo(() => {
    return {
      ...summarizeRunStatuses(runs),
      total: runs.length,
      active: runs.filter(isActiveRun).length,
      needsAttention: runs.filter(isAttentionRun).length,
    }
  }, [runs])
  const successRate = metrics.total ? Math.round(metrics.completed / metrics.total * 100) : 0

  return <div className="ops-dashboard">
    <section className="command-hero">
      <div>
        <Text className="panel-kicker">SECURITY OPERATIONS OVERVIEW</Text>
        <Title level={2}>安全态势总览</Title>
        <p>聚合代码审计、逆向分析与授权渗透任务，所有状态来自真实运行记录。</p>
      </div>
      <div className="command-actions">
        <Tag color={modules.length && modules.every((item) => item.available) ? "success" : "warning"}>{modules.length ? "模块状态见下方探针" : "模块状态未知"}</Tag>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/workbench?create=1')}>新建任务</Button>
      </div>
    </section>

    <section className="command-metrics">
      <Metric icon={<RadarChartOutlined />} label="最近任务数量" value={metrics.total} hint={`${metrics.active} 个正在运行`} tone="cyan" />
      <Metric icon={<ClockCircleOutlined />} label="运行中" value={metrics.active} hint="实时工作流" tone="blue" />
      <Metric icon={<CheckCircleOutlined />} label="已完成" value={metrics.completed} hint={`完成率 ${successRate}%`} tone="green" />
      <Metric icon={<ExclamationCircleOutlined />} label="需要关注" value={metrics.needsAttention} hint={`部分 ${metrics.partial} · 失败 ${metrics.failed} · 超时 ${metrics.timeout + metrics.unavailable}`} tone="red" />
    </section>

    <section className="status-breakdown" aria-label="任务状态明细">
      {[
        ['completed', '已完成', 'is-completed'], ['partial', '部分完成', 'is-partial'],
        ['failed', '失败', 'is-failed'], ['timeout', '超时', 'is-timeout'],
        ['unavailable', '不可用', 'is-unavailable'], ['running', '运行中', 'is-running'],
      ].map(([key, label, className]) => <span className={className} key={key}><b>{metrics[key]}</b><small>{label}</small></span>)}
    </section>

    <section className="dashboard-grid">
      <article className="glass-panel run-overview-card">
        <header className="panel-heading compact-heading">
          <div><Text className="panel-kicker">TASK ORCHESTRATION</Text><Title level={4}>任务编排</Title></div>
          <Button type="text" onClick={() => navigate('/workbench')}>进入工作台 <ArrowRightOutlined /></Button>
        </header>
        <div className="run-table-head"><span>任务</span><span>模块</span><span>进度</span><span>状态</span></div>
        <div className="run-overview-list">{runs.length ? runs.slice(0, 8).map((run) => {
          const progress = run.total_steps ? Math.min(100, Math.round(run.current_step / run.total_steps * 100)) : isSuccessfulRun(run) ? 100 : 0
          const route = routeFor(run)
          const ext = externalStatus(run)
          const bucket = classifyRunStatus(run)
          const statusForTag = route === 'penetration' && run.status === 'completed' ? bucket : run.status
          return <button type="button" className="run-overview-row" key={run.run_id} onClick={() => navigate(`/workbench?run=${run.run_id}`)}>
            <span><b>{run.name || scenarioLabel[run.scenario] || '未命名任务'}</b><small>{compactId(run.run_id)}</small></span>
            <Tag>{moduleLabel[route] || scenarioLabel[run.scenario] || route || '待识别'}</Tag>
            <span className="run-progress"><Progress percent={progress} showInfo={false} size="small" /><small>{progress}%</small></span>
            <span className="run-status-cell"><StatusTag status={statusForTag} /><small className={`run-state-detail is-${bucket}`}>{bucket === 'completed' ? '已验证完成' : bucket === 'running' ? '工作流进行中' : bucket === 'partial' ? '部分完成' : bucket === 'timeout' ? '外部执行超时' : bucket === 'unavailable' ? '外部状态不可用' : bucket === 'failed' ? '未完成' : externalLabel[ext] || bucket}</small>{route === 'penetration' && ext && <small>{externalLabel[ext] || ext}</small>}</span>
          </button>
        }) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无运行记录" />}</div>
      </article>

      <article className="glass-panel architecture-card">
        <header className="panel-heading compact-heading"><div><Text className="panel-kicker">LOOP ENGINEERING</Text><Title level={4}>统一决策闭环</Title></div><ApartmentOutlined className="heading-icon" /></header>
        <div className="loop-orbit">
          {['Goal', 'Intent', 'Execute', 'Evidence', 'Verify'].map((node, index) => <React.Fragment key={node}>
            <div className={`loop-node is-${index}`}><b>{node}</b><small>{['目标', '探索意图', '模块执行', '结构化证据', '独立验证'][index]}</small></div>
            {index < 4 && <ArrowRightOutlined />}
          </React.Fragment>)}
        </div>
        <div className="architecture-principles">
          <span><SafetyCertificateOutlined /><b>状态做硬</b><small>只有结构化事实进入系统状态</small></span>
          <span><CheckCircleOutlined /><b>完成不可自证</b><small>验证节点决定是否形成正式结论</small></span>
          <span><RadarChartOutlined /><b>反馈可追溯</b><small>事件、证据和决策保留完整链路</small></span>
        </div>
      </article>

      <article className="glass-panel module-readiness-card">
        <header className="panel-heading compact-heading"><div><Text className="panel-kicker">CAPABILITY MATRIX</Text><Title level={4}>模块就绪度</Title></div></header>
        <div className="readiness-grid">{modules.map((module) => <div key={module.id} className="readiness-item">
          <span><i className={module.available ? 'is-ready' : ''} /><b>{module.name}</b></span>
          <small>{module.adapter}</small>
          <Tag color={module.available ? 'success' : 'default'}>{module.available ? 'READY' : 'OFFLINE'}</Tag>
        </div>)}</div>
      </article>
    </section>
  </div>
}

function Metric({ icon, label, value, hint, tone }) {
  return <article className={`command-metric is-${tone}`}><i>{icon}</i><span><small>{label}</small><b>{value}</b><em>{hint}</em></span></article>
}
