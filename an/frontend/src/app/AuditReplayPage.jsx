import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  CaretRightOutlined,
  PauseOutlined,
  RedoOutlined,
  ReloadOutlined,
  StepForwardOutlined,
} from '@ant-design/icons'
import { Alert, Button, Empty, Progress, Select, Space, Spin, Table, Tag, Typography } from 'antd'
import { useNavigate, useParams } from 'react-router-dom'
import { getLedger, getRun, listRuns, thoughtProcessUrl } from '../api.js'
import { AgentNetwork } from './AgentNetwork.jsx'
import { AIThoughtTimeline } from './AIThoughtTimeline.jsx'
import { RuntimeStream } from './RuntimeStream.jsx'
import { compactId, deriveNetwork, projectSecurityEvents } from './runtimeModel.js'
import { StatusTag } from './StatusTag.jsx'

const { Text, Title } = Typography
function replayDelay(events, cursor, speed) {
  if (cursor <= 0) return 0
  const previous = new Date(events[cursor - 1]?.timestamp || 0).getTime()
  const next = new Date(events[cursor]?.timestamp || 0).getTime()
  const observed = Number.isFinite(previous) && Number.isFinite(next) ? Math.max(20, next - previous) : 650
  return Math.min(3000, Math.max(20, observed / speed))
}

export function AuditReplayPage() {
  const { runId } = useParams()
  const navigate = useNavigate()
  const [runs, setRuns] = useState([])
  const [runsTotal, setRunsTotal] = useState(0)
  const runsHasMore = runs.length < runsTotal
  const [runsLoadingMore, setRunsLoadingMore] = useState(false)
  const runsCursor = useRef(null)
  const [events, setEvents] = useState([])
  const [run, setRun] = useState(null)
  const [chainValid, setChainValid] = useState(null)
  const [loadingRuns, setLoadingRuns] = useState(true)
  const [loadingReplay, setLoadingReplay] = useState(false)
  const [error, setError] = useState('')
  const [runsError, setRunsError] = useState('')
  const [cursor, setCursor] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const runsInFlight = useRef(null)

  const refreshRuns = useCallback((silent = false) => {
    if (runsInFlight.current) return runsInFlight.current
    if (!silent) setLoadingRuns(true)
    const request = listRuns().then((data) => {
      if (!runsCursor.current) runsCursor.current = data.next_cursor
      setRunsTotal(data.total ?? data.runs?.length ?? 0)
      setRuns(current => {
        const latest = data.runs || []
        const seen = new Set(latest.map(item => item.run_id))
        const merged = [...latest, ...current.filter(item => !seen.has(item.run_id))]
        return merged.sort((left, right) =>
          Number(right.status === 'waiting_approval') - Number(left.status === 'waiting_approval'))
      })
      setRunsError('')
    }).catch((cause) => { setRunsError(cause.message) }).finally(() => {
      if (runsInFlight.current === request) runsInFlight.current = null
      setLoadingRuns(false)
    })
    runsInFlight.current = request
    return request
  }, [])

  useEffect(() => {
    refreshRuns()
    const timer = window.setInterval(() => refreshRuns(true), 10000)
    return () => window.clearInterval(timer)
  }, [refreshRuns])

  useEffect(() => {
    let disposed = false
    setPlaying(false)
    setCursor(0)
    setEvents([])
    setRun(null)
    setChainValid(null)
    setError('')
    if (!runId) return () => { disposed = true }
    setLoadingReplay(true)
    let inFlight = false
    let lastSequence = 0
    const refreshSelected = async () => {
      if (inFlight) return
      inFlight = true
      try {
        const nextRun = await getRun(runId)
        if (disposed) return
        setRun(nextRun)
        setRuns((current) => current.some((item) => item.run_id === nextRun.run_id)
          ? current
          : [nextRun, ...current])
        const ledger = await getLedger(runId, lastSequence)
        if (disposed) return
        const received = ledger.events || []
        if (received.length) {
          lastSequence = received.at(-1).sequence
          setEvents(current => [...current, ...received])
        }
        setChainValid(Boolean(ledger.chain_valid))
        setError('')
      } catch (cause) {
        if (!disposed) setError(cause.message)
      } finally {
        inFlight = false
        if (!disposed) setLoadingReplay(false)
      }
    }
    refreshSelected()
    const timer = window.setInterval(refreshSelected, 10000)
    return () => { disposed = true; window.clearInterval(timer) }
  }, [runId])

  useEffect(() => {
    if (!playing || !events.length) return undefined
    if (cursor >= events.length) {
      setPlaying(false)
      return undefined
    }
    const timer = window.setTimeout(() => {
      setCursor((current) => Math.min(events.length, current + 1))
    }, replayDelay(events, cursor, speed))
    return () => window.clearTimeout(timer)
  }, [playing, cursor, speed, events])

  const visibleEvents = useMemo(() => events.slice(0, cursor), [events, cursor])
  // The audit table follows the replay cursor as well. Showing all security
  // events while the stream is still paused would reveal future decisions.
  const securityEvents = useMemo(() => projectSecurityEvents(visibleEvents), [visibleEvents])
  const replayStatus = cursor >= events.length ? run?.status : 'running'
  const network = useMemo(
    () => deriveNetwork(visibleEvents, replayStatus),
    [visibleEvents, replayStatus],
  )
  const progress = events.length ? Math.round(cursor / events.length * 100) : 0

  function startOrPause() {
    if (!events.length) return
    if (playing) {
      setPlaying(false)
      return
    }
    if (cursor >= events.length) setCursor(0)
    setPlaying(true)
  }

  function reset() {
    setPlaying(false)
    setCursor(0)
  }

  function step() {
    setPlaying(false)
    setCursor((current) => Math.min(events.length, current + 1))
  }

  return <div className="replay-workspace">
    <aside className="glass-panel replay-run-panel">
      <div className="panel-heading">
        <div><Text className="panel-kicker">TASK AUDIT</Text><Title level={4}>任务与审批</Title></div>
        <Button type="text" icon={<ReloadOutlined />} loading={loadingRuns} onClick={() => refreshRuns()} />
      </div>
      {runsError && <Alert type="error" showIcon title="任务列表读取失败" description={runsError} />}
      <div className="replay-run-list">
        {runs.length ? runs.map((item) => <button
          type="button"
          key={item.run_id}
          className={`session-item ${runId === item.run_id ? 'is-active' : ''}`}
          onClick={() => navigate(`/audit/${item.run_id}`)}
        >
          <span>
            <b>{item.name || (item.scenario === 'unknown' ? '未命名任务' : item.scenario)}</b>
            <small>{item.scenario !== 'unknown' ? `${item.scenario} · ` : ''}{compactId(item.run_id)}</small>
          </span>
          <StatusTag status={item.status} />
        </button>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无任务" />}
      </div>
      {runsHasMore && <Button block loading={runsLoadingMore} onClick={async () => { setRunsLoadingMore(true); try { const data = await listRuns({ before: runsCursor.current, limit: 100 }); runsCursor.current = data.next_cursor; setRunsTotal(data.total ?? 0); setRuns(current => { const seen = new Set(current.map(item => item.run_id)); const merged = [...current, ...(data.runs || []).filter(item => !seen.has(item.run_id))]; return merged.sort((left, right) => Number(right.status === 'waiting_approval') - Number(left.status === 'waiting_approval')) }) } catch (cause) { setRunsError(cause.message) } finally { setRunsLoadingMore(false) } }}>加载更多任务</Button>}
    </aside>

    <main className="replay-main">
      {error && <Alert type="error" showIcon closable title="无法读取审计回放" description={error} onClose={() => setError('')} />}
      {(run?.status === 'waiting_approval' || run?.mcp_pending_approvals?.length > 0) &&
        <Alert type="warning" showIcon style={{ marginBottom: 12 }}
          title="当前任务有待处理审批"
          description={<Button type="link" onClick={() => navigate(`/workbench?run=${runId}`)}>前往任务编排处理审批</Button>} />}
      {!runId ? <div className="glass-panel replay-empty"><Empty description="请从左侧选择任务，查看审计记录和审批状态" /></div>
        : loadingReplay ? <div className="glass-panel replay-empty"><Spin /> 正在读取持久化账本…</div>
          : !events.length ? <div className="glass-panel replay-empty"><Empty description="该任务没有可回放的账本事件" /></div>
            : <>
              <div className="page-intro replay-intro">
                <div>
                  <Text className="panel-kicker">AUDIT PROCESS REPLAY</Text>
                  <Title level={2}>{run?.name || run?.scenario || '任务流程回放'}</Title>
                  <p>按照首次运行的事件顺序和相对时间同步重放 AI 实时流、AI 协作图与执行摘要。</p>
                </div>
                <div className="intro-tags">
                  <Tag color={chainValid ? 'success' : 'error'}>{chainValid ? '账本链校验通过' : '账本链校验失败'}</Tag>
                  <Tag>{run?.scenario} · {compactId(runId)}</Tag>
                </div>
              </div>

              <section className="glass-panel playback-bar">
                <Space wrap>
                  <Button type="primary" icon={playing ? <PauseOutlined /> : <CaretRightOutlined />} onClick={startOrPause}>
                    {playing ? '暂停' : cursor > 0 && cursor < events.length ? '继续' : '启动'}
                  </Button>
                  <Button icon={<StepForwardOutlined />} onClick={step} disabled={cursor >= events.length}>单步</Button>
                  <Button icon={<RedoOutlined />} onClick={reset}>重新开始</Button>
                  <Select value={speed} onChange={setSpeed} options={[0.5, 1, 2, 4, 8].map((value) => ({ value, label: `${value}×` }))} />
                </Space>
                <div className="playback-progress">
                  <Progress percent={progress} showInfo={false} strokeColor={{ from: '#55d9ff', to: '#a979ff' }} />
                  <span>{cursor} / {events.length} 个事件 · {progress}%</span>
                </div>
              </section>

              <section className="glass-panel replay-security-panel" style={{ padding: 20 }}>
                <div className="panel-heading"><div><Text className="panel-kicker">GUARDRAIL & APPROVAL AUDIT</Text><Title level={4}>审计与拦截</Title></div><Tag color={securityEvents.length ? 'gold' : 'default'}>{securityEvents.length} 条记录</Tag></div>
                {securityEvents.length ? <Table size="small" pagination={{ pageSize: 8 }} rowKey="event_id" dataSource={securityEvents} columns={[
                  { title: '时间', dataIndex: 'timestamp', render: value => new Date(value).toLocaleString() },
                  { title: '事件', dataIndex: 'event_type' },
                  { title: '动作', dataIndex: 'action' },
                  { title: '风险', dataIndex: 'risk_level', render: value => value == null ? '—' : `R${value}` },
                  { title: '工具', dataIndex: 'tool', render: value => value || '—' },
                  { title: '策略 / 原因', render: (_, row) => [row.policy_ids.join('、'), row.reason].filter(Boolean).join(' · ') || '—' },
                ]} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="该任务没有策略检查、审批或拦截记录" />}
              </section>

              <div className="replay-stage-grid">
                <section className="glass-panel replay-stage is-stream">
                  <div className="panel-heading"><div><Text className="panel-kicker">LIVE STREAM REPLAY</Text><Title level={4}>AI 实时流</Title></div><Tag color={playing ? 'processing' : cursor >= events.length ? 'success' : 'default'}>{playing ? '回放中' : cursor >= events.length ? '已完成' : '等待启动'}</Tag></div>
                  <RuntimeStream events={visibleEvents} replaying={playing} replay />
                </section>
                <section className="glass-panel replay-stage is-network">
                  <div className="panel-heading"><div><Text className="panel-kicker">AGENT COLLABORATION</Text><Title level={4}>AI 协作图</Title></div><Tag>{network.completed} / {network.roles.length}</Tag></div>
                  <AgentNetwork network={network} eventCount={visibleEvents.length} />
                </section>
                <section className="glass-panel replay-stage is-summary">
                  <div className="panel-heading"><div><Text className="panel-kicker">EXECUTION SUMMARY</Text><Title level={4}>执行摘要</Title></div><Tag color={cursor >= events.length ? 'success' : 'processing'}>{cursor >= events.length ? '流程已重现' : '随回放更新'}</Tag></div>
                  <AIThoughtTimeline events={visibleEvents} runStatus={replayStatus} downloadUrl={cursor >= events.length ? thoughtProcessUrl(runId) : ''} />
                </section>
              </div>
            </>}
    </main>
  </div>
}
