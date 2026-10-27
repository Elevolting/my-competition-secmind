import React, { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { getDashboard, getIntegrationStatus, listModules } from '../api.js'
import { RobotCanvas } from './RobotCanvas.jsx'
import './cockpit.css'

const scenes = [['code_audit', '代码审计'], ['reverse', '逆向分析'], ['penetration', '渗透测试'], ['incident_response', '日志留痕'], ['log_analysis', '日志分析'], ['other', '其他任务']]

export function CockpitPage() {
  const [data, setData] = useState(null)
  const [modules, setModules] = useState(null)
  const [integration, setIntegration] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const refreshRef = useRef(null)
  const statusBubbleRef = useRef(null)
  useEffect(() => {
    let alive = true
    let pending = false
    const refresh = async () => {
      if (pending) return
      pending = true
      setLoading(true)
      const results = await Promise.allSettled([getDashboard(), listModules(), getIntegrationStatus()])
      if (alive) {
        setData(results[0].status === 'fulfilled' ? results[0].value : null)
        setModules(results[1].status === 'fulfilled' ? results[1].value.modules : null)
        setIntegration(results[2].status === 'fulfilled' ? results[2].value : null)
        setError(results.some((item) => item.status === 'rejected') ? '部分数据读取失败，相关指标显示为 —；请重试。' : '')
        setLoading(false)
      }
      pending = false
    }
    refreshRef.current = refresh
    refresh()
    const timer = window.setInterval(refresh, 10000)
    return () => { alive = false; window.clearInterval(timer); refreshRef.current = null }
  }, [])
  const host = data?.host
  const inventory = host?.inventory
  const counts = { ...(data?.scenes || {}) }
  const known = new Set(scenes.map(([key]) => key))
  counts.other = (counts.other || 0) + Object.entries(counts).reduce((total, [key, value]) => total + (!known.has(key) ? value : 0), 0)
  const maxScene = Math.max(1, ...Object.values(counts))
  const days = data?.daily_created || []
  const maxDay = Math.max(1, ...days.map((day) => day.count))
  const go = (path) => window.location.assign(path)
  const summary = data ? `共 ${data.total} 个任务，${data.completed} 个已完成，${data.active} 个执行中，${data.needs_attention} 个需要关注。` : loading ? '正在读取运行记录…' : '运行记录暂不可用。'
  const monitorState = !data ? 'loading' : data.needs_attention > 0 ? 'attention' : data.active > 0 ? 'active' : 'idle'
  const monitorValue = data ? (data.needs_attention > 0 ? data.needs_attention : data.active) : null
  return <div className="hero-shell cockpit-host"><RobotCanvas statusBubbleRef={statusBubbleRef} /><section className="cockpit-overlay">
    <button className="cockpit-brand" type="button" onClick={() => go('/workbench')} aria-label="打开任务工作台"><img className="cockpit-brand-logo" src="/secmind-logo-dark.png" alt="SecMind" /></button>
    <header className="cockpit-head"><div className="cockpit-head-copy"><span className="cockpit-kicker">SecMind</span><h1>具备自主决策能力的通用网络安全智能体</h1><p>全部已保存任务 · 每 10 秒刷新 · 统计时区：上海</p></div><div className="cockpit-risk"><span>全接口监听</span><b>{inventory ? inventory.listeners.filter(x => x.wildcard).length : "—"}</b><small>本机暴露面</small></div></header>
    {error && <div className="cockpit-data-warning" role="alert">{error}</div>}
    <div className="cockpit-metrics">
      <Metric label="安全任务" value={data?.total} hint="全部任务" onClick={() => go('/workbench')} />
      <Metric label="已完成" value={data?.completed} hint="按实际执行状态" onClick={() => go('/workbench')} />
      <Metric label="需关注任务" value={data?.needs_attention} hint="失败、部分完成或待审批" tone="gold" onClick={() => go('/workbench')} />
      <Metric label="执行中" value={data?.active} hint="不含待审批" onClick={() => go('/workbench')} />
    </div>
    <div className="cockpit-grid">
      <aside className="cockpit-left">
        <section className="cockpit-card scene-card"><CardTitle kicker="SCENE DISTRIBUTION" title="任务场景分布" icon="↗" />
          <div className="scene-list">{scenes.map(([key, label]) => <button className="scene-row" type="button" key={key} onClick={() => go('/workbench')}><span><i className={`dot ${key}`} />{label}</span><b>{data ? counts[key] || 0 : '—'}</b><i className="bar"><em style={{ width: `${(counts[key] || 0) / maxScene * 100}%` }} /></i></button>)}</div>
          <CardTitle kicker="7-DAY TREND" title="近七日新建任务" icon="↗" />
          <div id="cockpit-trend" className="trend-chart" aria-label="近七日新建任务数量">{days.map((day) => <span key={day.date} title={`${day.date}：${day.count} 个新建任务`}><i style={{ height: `${day.count / maxDay * 100}px` }} /><small>{day.date.slice(5)}</small><small>{day.count}</small></span>)}{!data && <span className="cockpit-empty">{loading ? '正在读取趋势…' : '趋势暂不可用'}</span>}</div>
        </section>
        <section className="cockpit-card capacity-card"><CardTitle kicker="RUNTIME CAPABILITIES" title="模块与工具" icon="⌘" />
          <div className="capacity-list"><div><b>{integration?.native_tool_count ?? '—'}</b><small>已注册工具</small></div><div><b>{modules ? modules.filter((item) => item.available).length : '—'}</b><small>可用模块</small></div><div><b>{data?.pending_approvals ?? '—'}</b><small>待审批任务</small></div></div>
          <p className="cockpit-empty-panel">{inventory ? `${inventory.hostname} · ${inventory.processes.length} 个进程 · ${inventory.listeners.length} 个监听端口；采集于 ${new Date(inventory.collected_at).toLocaleTimeString()}` : loading && !data ? '正在读取本机快照…' : '尚无本机快照，请到日志留痕页面启动采集。'}</p>
        </section>
      </aside>
      <main className="cockpit-center"><MonitorNotice followRef={statusBubbleRef} data={data} value={monitorValue} state={monitorState} /></main>
      <aside className="cockpit-right"><section className="cockpit-card rank-card"><CardTitle kicker="MODULE STATUS" title="模块连接状态" icon="⌘" />
        {modules ? modules.map((item) => <div className="rank-row cockpit-module-row" key={item.id}><span><b>{item.id === 'incident_response' ? '日志留痕' : item.name}</b><i>{item.id === 'incident_response' ? (host?.running ? '本机采集中' : '本机采集器已就绪') : item.available ? '接口可用' : item.error || '接口不可用'}</i></span><strong>{item.id === 'incident_response' ? (host?.running ? '采集中' : '可启动') : item.available ? '已连接' : '离线'}</strong></div>) : <p className="cockpit-empty-panel">{loading ? '正在读取模块状态…' : '模块状态暂不可用'}</p>}
        <CardTitle kicker="LOCAL LISTENERS" title="本机监听端口" icon="♨" />{inventory ? inventory.listeners.slice(0, 5).map((item) => <div className="rank-row cockpit-module-row" key={`${item.address}:${item.port}`}><span><b>{item.process}</b><i>{item.address}</i></span><strong>{item.port}</strong></div>) : <p className="cockpit-empty-panel">{loading && !data ? '正在读取本机监听端口…' : '尚未采集'}</p>}
        {inventory && <p className="cockpit-empty-panel">显示前五个监听端口。{inventory.errors?.length ? '部分采集失败，请查看详情。' : ''}</p>}<button className="cockpit-workbench-link" type="button" onClick={() => go('/incident-response')}>查看日志留痕</button>
      </section></aside>
    </div>
    <footer className="cockpit-summary"><span>↑</span><div><i>RUN SUMMARY</i><b>{summary}<span className="cockpit-summary-followup">{data ? `更新时间 ${new Date(data.generated_at).toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' })}` : '暂无可用统计'}</span></b></div><button type="button" disabled={loading} onClick={() => refreshRef.current?.()}>{loading ? '刷新中…' : '刷新态势'}</button></footer>
  </section></div>
}
function CardTitle({ kicker, title, icon }) { return <div className="card-title"><span><i>{kicker}</i><b>{title}</b></span><em>{icon}</em></div> }
function Metric({ label, value, hint, tone = 'cyan', onClick }) { return <button className={`metric ${tone}`} type="button" onClick={onClick}><span>{label}：</span><b>{value ?? '—'}</b><small>{hint}</small></button> }
function MonitorNotice({ followRef, data, value, state }) {
  const [expanded, setExpanded] = useState(false)
  const status = state === 'attention' ? '需要关注' : state === 'active' ? '任务执行中' : state === 'idle' ? '运行正常' : '正在同步'
  return createPortal(<div ref={followRef} className={`cockpit-monitor-notice${expanded ? ' is-expanded' : ''}`} data-state={state}>
    {expanded ? <section className="cockpit-monitor-dialog" role="status" aria-label="实时任务概况">
      <header><span className="cockpit-monitor-status-dot" /><div><b>任务概况</b><small>{status}</small></div><button type="button" onClick={() => setExpanded(false)} aria-label="收起任务概况">×</button></header>
      <div className="cockpit-monitor-stats">
        <div><b>{data?.total ?? '—'}</b><small>总任务</small></div>
        <div><b>{data?.completed ?? '—'}</b><small>已完成</small></div>
        <div><b>{data?.active ?? '—'}</b><small>执行中</small></div>
        <div className="needs-attention"><b>{data?.needs_attention ?? '—'}</b><small>需关注</small></div>
      </div>
    </section> : <button className="cockpit-monitor-orb" type="button" aria-label={`打开任务概况，${status}`} aria-expanded="false" onClick={() => setExpanded(true)}><span aria-hidden="true">{value ?? '—'}</span></button>}
  </div>, document.body)
}
