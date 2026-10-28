import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiOutlined,
  AuditOutlined,
  BookOutlined,
  BranchesOutlined,
  CopyOutlined,
  DatabaseOutlined,
  DeleteOutlined,
  DeploymentUnitOutlined,
  EditOutlined,
  FileTextOutlined,
  LinkOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
} from '@ant-design/icons'
import { Alert, App, Button, Drawer, Empty, Form, Input, Modal, Popconfirm, Segmented, Select, Space, Statistic, Tag, Typography, Tooltip } from 'antd'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  eventSocketUrl,
  getLedger,
  getBatch,
  getReport,
  refreshRunReport,
  retryRun,
  cancelRun,
  deleteRun,
  getRun,
  listRuns,
  submitApproval,
  decideMcpApproval,
  thoughtProcessUrl,
  listModules,
  getRunExperienceUses,
  getTaskBudgetDefaults,
  getRunSettings,
  updateRunSettings,
} from '../api.js'
import { AgentNetwork } from './AgentNetwork.jsx'
import { AIThoughtTimeline } from './AIThoughtTimeline.jsx'
import { RuntimeStream } from './RuntimeStream.jsx'
import {
  localizeFinding,
  localizePublicText,
  severityLabels,
} from './localization.js'
import { compactId, copyVerifiedOutput, deriveNetwork, getVerifiedOutputs, mergeLedgerEvents, projectToolCalls } from './runtimeModel.js'
import { StatusTag } from './StatusTag.jsx'
import { TaskModal } from './TaskModal.jsx'
import { networkPolicyOptions } from './network-policy-presets.js'
import { retryTaskBudget, validTaskBudget } from './task-budget.js'
import { TaskBudgetFields } from './TaskBudgetFields.jsx'
import './workbench-header.css'
import { ModuleFlow } from './ModuleFlow.jsx'
import { BlackboardGraph } from './BlackboardGraph.jsx'
import { AssetCoverageGraph } from './AssetCoverageGraph.jsx'
import { TrafficEvidencePanel } from './TrafficEvidencePanel.jsx'
import { RetestConclusion, RetestPanel } from './RetestPanel.jsx'
import { SideQuestionPanel } from './SideQuestionPanel.jsx'
import { LogAnalysisPanel } from './LogAnalysisPanel.jsx'
import { EvidenceDrawer } from './EvidenceDrawer.jsx'
import { ReportExportButtons } from './ReportExportButtons.jsx'

const { Text, Title, Paragraph } = Typography

function formatTokens(value) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function TaskSettingsDrawer({ open, runId, onClose, onSaved, onDeleted }) {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [settings, setSettings] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!open || !runId) return
    setLoading(true); setError(''); setSettings(null)
    getRunSettings(runId).then((value) => {
      setSettings(value)
      form.setFieldsValue({ ...value, target_scope_text: (value.target_scope || []).join('\n') })
    }).catch((reason) => setError(reason.message)).finally(() => setLoading(false))
  }, [open, runId, form])
  const save = async (values) => {
    if (!settings) return
    setSaving(true); setError('')
    try {
      const targetScope = String(values.target_scope_text || '').split(/[\r\n,，;；]+/).map((item) => item.trim()).filter(Boolean)
      const updated = await updateRunSettings(runId, {
        expected_revision: settings.revision,
        name: values.name,
        autonomy_policy: values.autonomy_policy,
        target_scope: [...new Set(targetScope)],
      })
      setSettings(updated)
      form.setFieldsValue({ ...updated, target_scope_text: (updated.target_scope || []).join('\n') })
      onSaved(updated)
    } catch (reason) { setError(reason.message) } finally { setSaving(false) }
  }
  const remove = async () => {
    setDeleting(true); setError('')
    try {
      await deleteRun(runId)
      onDeleted(runId)
    } catch (reason) { setError(reason.message) } finally { setDeleting(false) }
  }
  const canDelete = settings && ['completed', 'partial', 'failed', 'denied'].includes(settings.status)
  return <Drawer title="任务详情与编辑" open={open} onClose={onClose} width="min(520px, 100vw)" destroyOnHidden>
    {loading && <div className="route-loading" role="status">正在读取任务设置…</div>}
    {!loading && settings && <Form form={form} layout="vertical" onFinish={save} disabled={saving || deleting}>
      <Alert type={settings.can_edit_execution_settings ? 'info' : 'warning'} showIcon
        message={settings.can_edit_execution_settings ? '设置会实时应用到后续工具调用和审批判断。' : settings.can_edit_approval_policy ? '审批策略可实时修改' : '当前任务只支持修改名称'}
        description={settings.can_edit_execution_settings ? '任务目标与输入材料为只读；任务执行期间修改授权范围后，尚未发出的调用会按新范围校验。' : settings.can_edit_approval_policy ? '受限 POST 任务的授权范围由单次授权固定。' : '已启动的 SecMind 分析合约不能在执行中调整审批策略和授权范围。'} />
      <Form.Item name="name" label="任务名称" rules={[{ required: true, whitespace: true, max: 120 }]}><Input maxLength={120} showCount /></Form.Item>
      <Form.Item name="objective" label="任务目标"><Input.TextArea rows={3} readOnly /></Form.Item>
      <Form.Item name="autonomy_policy" label="审批策略"><Select disabled={!settings.can_edit_approval_policy} options={[{ value: 'graded', label: '分级审批' }, { value: 'approval_all', label: '全部审批' }, { value: 'automatic', label: '自动执行（免 R2 审批）' }, { value: 'automatic_r3', label: '自动执行（免除所有审批）' }]} /></Form.Item>
      <Form.Item name="target_scope_text" label="授权范围" extra="每行一个目标，也支持逗号或分号分隔"><Input.TextArea rows={5} readOnly={!settings.can_edit_execution_settings} /></Form.Item>
      <Form.Item label="任务约束"><Input.TextArea value={(settings.constraints || []).join('\n')} rows={3} readOnly /></Form.Item>
      {error && <Alert type="error" showIcon message={error} />}
      <div className="task-settings-actions">
        <Space><Button onClick={onClose}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>保存设置</Button></Space>
        <Tooltip title={canDelete ? '' : '请先终止任务，等待任务结束后再删除'}>
          <span><Popconfirm
            title={`删除任务“${settings.name || runId}”？`}
            description="本地任务、问答和工作区将永久删除；外部项目及跨任务共享经验保留。"
            okText="确认删除" cancelText="取消" okButtonProps={{ danger: true, loading: deleting }}
            onConfirm={remove} disabled={!canDelete || saving || deleting}
          ><Button danger icon={<DeleteOutlined />} disabled={!canDelete || saving || deleting}>删除任务</Button></Popconfirm></span>
        </Tooltip>
      </div>
    </Form>}
  </Drawer>
}

function usageCaption(item) {
  const usage = item?.usage
  if (!usage?.token_usage_available) {
    if (['completed', 'partial', 'failed', 'denied'].includes(item?.status)) return 'Token 用量未知'
    return usage?.model_call_count ? 'Token 用量统计中' : 'Token 用量待 Provider 返回'
  }
  const total = Number(usage.total_tokens || 0)
  return `Token ${formatTokens(total)}`
}

const assetRouteLabels = {
  code_audit: '代码审计',
  reverse: '逆向分析',
  penetration: '渗透测试',
  incident_response: '日志留痕',
  unsupported: '人工研判',
}

function displayToolStatus(status) {
  if (status === 'simulated_completed') return ['已模拟（未执行）', 'warning']
  if (status === 'success' || status === 'completed') return ['已完成', 'success']
  if (status === 'running') return ['执行中', 'processing']
  if (status === 'ready') return ['候选', 'blue']
  if (status === 'failed' || status === 'error') return ['失败', 'error']
  if (status === 'timeout') return ['超时', 'error']
  if (status === 'interrupted') return ['已中断', 'warning']
  if (status === 'cancelled') return ['已取消', 'default']
  if (status === 'denied') return ['已拒绝', 'error']
  return [status || '未知', 'error']
}

function AssetUsageDrawer({ open, onClose, loading, events, experiences, run }) {
  const actualTools = useMemo(() => projectToolCalls(events), [events])

  const toolCalls = actualTools

  const actualToolCount = actualTools.length
  const routeLabel = assetRouteLabels[run?.module_route] || '通用安全分析'

  return <Drawer
    title={<span className="asset-drawer-title"><DatabaseOutlined /> 资产调用</span>}
    placement="right"
    width="min(480px, 100vw)"
    open={open}
    onClose={onClose}
    destroyOnHidden
  >
    <div className="asset-drawer">
      <Alert type="info" showIcon title={run ? `${routeLabel}资产视图` : '通用资产预览'} description="以下内容只显示当前任务账本和经验库中实际存在的记录。" />
      <section className="asset-section">
        <header><div><Text className="panel-kicker">RUNTIME ASSETS</Text><Title level={5}>AI 使用的工具</Title></div><Tag color={actualToolCount ? 'blue' : 'default'}>{actualToolCount ? `${actualToolCount} 次实际调用` : '暂无实际调用'}</Tag></header>
        {loading && <div className="asset-empty"><ApiOutlined />正在读取任务资产。</div>}
        <div className="asset-tool-list">
          {!toolCalls.length && !loading && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前任务没有实际工具调用" />}
          {toolCalls.map((item) => {
            const [statusLabel, statusColor] = displayToolStatus(item.status)
            return <article className={`asset-tool-row ${item.placeholder ? 'is-display-only' : ''}`} key={item.id}>
              <span className="asset-icon"><ApiOutlined /></span>
              <div><b>{item.tool}</b><small>{item.version || '运行时工具'}{item.duration != null ? ` · ${item.duration} ms` : ''}</small><p>{item.description}</p>{item.error && <p title={item.error}>失败原因：{item.error}</p>}</div>
              <Tag color={statusColor}>{statusLabel}</Tag>
            </article>
          })}
        </div>
      </section>

      <section className="asset-section">
        <header><div><Text className="panel-kicker">PLANNER MEMORY</Text><Title level={5}>实际注入规划的经验</Title></div><Tag color={experiences.length ? 'gold' : 'default'}>{experiences.length} 条使用记录</Tag></header>
        {loading && <div className="asset-empty"><BookOutlined />正在读取经验库。</div>}
        <div className="asset-memory-list">
          {!experiences.length && !loading && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前任务没有实际注入规划的经验" />}
          {experiences.map((item, index) => <article className={`asset-memory-row ${item.displayOnly ? 'is-display-only' : ''}`} key={`${item.experience_id}-${item.version}-${index}`}>
            <span className="asset-icon is-memory"><BookOutlined /></span>
            <div><b>{run?.run_id && item.experience_id ? <Link to={`/experiences?experience=${encodeURIComponent(item.experience_id)}&run=${encodeURIComponent(run.run_id)}`}
              data-testid="task-experience-link" data-experience-id={item.experience_id} aria-label={`查看经验 ${item.title}`}>{item.title}</Link> : item.title}</b><p>{item.summary}</p><small>{item.source_run_id ? `来源任务：${item.source_run_id.slice(0, 12)}` : '人工经验'} · 注入时 v{item.version}</small></div>
            <Tag color={item.model_cited ? 'success' : 'default'}>{item.model_cited ? '模型声明采用' : '已注入；未声明采用'}</Tag>
          </article>)}
        </div>
      </section>
    </div>
  </Drawer>
}

function TaskStatusPanel({ run, events }) {
  if (!run) return <div className="score-empty">
    <SafetyCertificateOutlined />
    <b>任务状态</b>
    <span>新建任务后，系统会在这里显示模块路由、执行进度和证据统计。</span>
  </div>
  const routeLabels = { code_audit: '代码审计', reverse: '逆向分析', log_analysis: '日志分析', penetration: '渗透测试', unsupported: '人工研判' }
  const externalLabels = {
    submitted: '已提交，等待外部执行',
    running: '外部执行中',
    partial: '外部执行部分完成',
    completed: '外部目标已确认完成',
    complete: '外部目标已确认完成',
    succeeded: '外部目标已确认完成',
    success: '外部目标已确认完成',
    failed: '外部执行失败',
    denied: '外部执行被拒绝',
    cancelled: '外部执行已取消',
    stopped: '外部执行已停止',
    timeout: '外部执行超时',
    unavailable: '外部状态不可用',
  }
  const externalStatus = run.external_execution?.status
  const mcpExecution = run.routing?.execution_backend === 'mcp'
  const externalText = mcpExecution ? 'MCP 工具直接执行' : externalLabels[externalStatus] || (run.module_route === 'penetration' ? '等待外部渗透状态' : '不适用')
  return <div className="score-panel task-status-panel">
    <div className="score-heading"><span><SafetyCertificateOutlined /><b>任务状态</b></span><StatusTag status={run.status} /></div>
    <div className="score-metrics">
      <Statistic title="执行步骤" value={run.current_step ?? 0} suffix={`/ ${run.total_steps ?? 0}`} />
      <span><small>分析模块</small><b>{routeLabels[run.module_route] || run.module_route || '待识别'}</b></span>
      <span><small>输入材料</small><b>{run.input_artifact_count ?? '—'} 个文件</b></span>
      <span><small>账本事件</small><b>{events.length}</b></span>
      <span><small>外部执行</small><b>{externalText}</b></span>
    </div>
    <Alert type={!mcpExecution && run.module_route === 'penetration' && !['completed', 'complete', 'succeeded', 'success', 'failed', 'denied', 'timeout', 'unavailable', 'stopped'].includes(externalStatus) ? 'warning' : 'info'} showIcon title={mcpExecution ? externalText : run.module_route === 'penetration' ? externalText : '统一文件分析流程'} description={mcpExecution ? '当前任务由 MCP 工具执行，进度与结果以工具记录和验证报告为准。' : run.module_route === 'penetration' ? '仅在 Security Runtime 项目进入终态且黑板存在目标完成证据后，任务才会标记为完成。' : '所有题目通过单文件分析、AI辅助文件分析或题库格式化文件分析进入对应安全模块；结果以可验证证据为准。'} />
  </div>
}

export function WorkbenchPage() {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const location = useLocation()
  const [runs, setRuns] = useState([])
  const [runsTotal, setRunsTotal] = useState(0)
  const runsHasMore = runs.length < runsTotal
  const [runsLoadingMore, setRunsLoadingMore] = useState(false)
  const runsCursor = useRef(null)
  const runsRequest = useRef(null)
  const runsRequestSequence = useRef(0)
  const [selectedId, setSelectedId] = useState(
    () => new URLSearchParams(location.search).get('run') || '',
  )
  const selectedIdRef = useRef(selectedId)
  selectedIdRef.current = selectedId
  const [batchId, setBatchId] = useState(() => new URLSearchParams(location.search).get('batch') || '')
  const batchIdRef = useRef(batchId)
  batchIdRef.current = batchId
  const [batch, setBatch] = useState(null)
  const [batchError, setBatchError] = useState('')
  const [run, setRun] = useState(null)
  const [events, setEvents] = useState([])
  const [report, setReport] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [settingsRunId, setSettingsRunId] = useState('')
  const [view, setView] = useState(() => new URLSearchParams(location.search).get('view') === 'result' ? 'result' : 'stream')
  const [streamConnected, setStreamConnected] = useState(false)
  const [modules, setModules] = useState([])
  const [refreshingReport, setRefreshingReport] = useState(false)
  const [retrySource, setRetrySource] = useState(null)
  const [retryBudget, setRetryBudget] = useState(null)
  const [retryBudgetLimits, setRetryBudgetLimits] = useState(null)
  const [retryNetworkPolicy, setRetryNetworkPolicy] = useState('inherit')
  const [retrying, setRetrying] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [approvalBusy, setApprovalBusy] = useState(false)
  const [mcpApprovalBusy, setMcpApprovalBusy] = useState('')
  const mcpApprovalInFlight = useRef(false)
  const [approvalQueued, setApprovalQueued] = useState(null)
  const [approvalError, setApprovalError] = useState('')
  const approvalInFlight = useRef(false)
  const retryRequest = useRef(null)
  const [assetDrawerOpen, setAssetDrawerOpen] = useState(false)
  const [assetRunId, setAssetRunId] = useState('')
  const [assetLoading, setAssetLoading] = useState(false)
  const [assetExperiences, setAssetExperiences] = useState([])
  const assetRequestToken = useRef(0)
  const reportRefreshInFlight = useRef(false)
  const socketRef = useRef(null)
  const lastSequence = useRef(0)
  // Track HTTP catch-up independently: a websocket can deliver a later event
  // while an earlier ledger page is still in flight.
  const ledgerCursor = useRef({ runId: '', sequence: 0 })
  const refreshToken = useRef(0)
  const copyOutput = async (value) => {
    try {
      await copyVerifiedOutput(value)
      message.success('Flag 已复制')
    } catch {
      message.error('复制失败，请手动选择 Flag')
    }
  }
  const refreshRequest = useRef({ runId: '', promise: null })
  /** @type {[{ runId: string, status: 'idle' | 'loading' | 'ready' | 'not_ready' | 'error', error: string }, React.Dispatch<React.SetStateAction<{ runId: string, status: 'idle' | 'loading' | 'ready' | 'not_ready' | 'error', error: string }>>]} */
  const [reportRead, setReportRead] = useState({ runId: '', status: 'idle', error: '' })
  const [reportReading, setReportReading] = useState(false)
  /** @type {[{ runId: string, evidenceId: string } | null, React.Dispatch<React.SetStateAction<{ runId: string, evidenceId: string } | null>>]} */
  const [selectedEvidence, setSelectedEvidence] = useState(null)
  const reportFailedRun = useRef('')
  const reportReadSequence = useRef(0)
  /** @type {React.RefObject<{ runId: string, promise: Promise<void> } | null>} */
  const reportReadRequest = useRef(null)

  /** @param {Error & { status?: number }} cause @param {string} runId @param {string} method */
  const recordReportFailure = useCallback((cause, runId, method) => {
    const notReady = cause.status === 409
    reportFailedRun.current = notReady ? '' : runId
    setReport(null)
    setSelectedEvidence(null)
    setReportRead({ runId, status: notReady ? 'not_ready' : 'error',
      error: `${method} /api/v1/runs/${encodeURIComponent(runId)}/report${method === 'POST' ? '/refresh' : ''} · ${cause.status ? `HTTP ${cause.status}` : '网络或报告数据错误'} · ${cause.message}` })
  }, [])

  /**
   * Share reads across polling and manual retry. Failures stay visible until
   * explicit retry/refresh rather than vanishing on the next poll.
   * @param {string} runId
   * @returns {Promise<void>}
   */
  const readReport = useCallback(async (runId) => {
    if (!runId || runId !== selectedIdRef.current || reportRefreshInFlight.current) return
    if (reportReadRequest.current?.runId === runId) return reportReadRequest.current.promise
    const sequence = ++reportReadSequence.current
    const isCurrent = () => sequence === reportReadSequence.current && runId === selectedIdRef.current
    reportFailedRun.current = ''
    setReportReading(true)
    setReportRead(current => current.runId === runId && current.status === 'ready' ? current : { runId, status: 'loading', error: '' })
    const request = (async () => {
      try {
        const nextReport = await getReport(runId)
        if (!isCurrent()) return
        if (!nextReport || nextReport.run_id !== runId || typeof nextReport.executive_summary !== 'string') {
          throw new TypeError(`任务 ${runId} 返回了不匹配或缺少摘要的报告；请重新读取`)
        }
        setReport(nextReport)
        setReportRead({ runId, status: 'ready', error: '' })
      } catch (cause) {
        if (!isCurrent()) return
        if (!(cause instanceof Error)) throw cause
        recordReportFailure(cause, runId, 'GET')
      } finally {
        if (isCurrent()) setReportReading(false)
      }
    })()
    reportReadRequest.current = { runId, promise: request }
    try { await request }
    finally { if (reportReadRequest.current?.promise === request) reportReadRequest.current = null }
  }, [recordReportFailure])

  const refreshRuns = useCallback(async (force = false) => {
    if (!force && runsRequest.current?.promise) return runsRequest.current.promise
    const sequence = ++runsRequestSequence.current
    const request = (async () => {
      const data = await listRuns()
      if (sequence !== runsRequestSequence.current) return data
      if (!runsCursor.current) runsCursor.current = data.next_cursor
      setRunsTotal(data.total ?? data.runs?.length ?? 0)
      setRuns(current => {
        const latest = data.runs || []
        const seen = new Set(latest.map(item => item.run_id))
        return [...latest, ...current.filter(item => !seen.has(item.run_id))]
      })
      if (data.runs?.length) {
        setSelectedId((currentId) => currentId || (batchIdRef.current ? '' : data.runs[0].run_id))
      }
      return data
    })()
    runsRequest.current = { sequence, promise: request }
    try {
      return await request
    } finally {
      if (runsRequest.current?.promise === request) runsRequest.current = null
    }
  }, [])

  useEffect(() => {
    if (!batchId) { setBatch(null); setBatchError(''); return undefined }
    let alive = true
    const refreshBatch = async () => {
      try {
        const result = await getBatch(batchId)
        if (alive) { setBatch(result); setBatchError('') }
      } catch (error) {
        if (alive) { setBatch(null); setBatchError(error.message) }
      }
    }
    refreshBatch()
    const timer = setInterval(refreshBatch, 3000)
    return () => { alive = false; clearInterval(timer) }
  }, [batchId])

  // Module availability can lag behind the frontend (for example when the
  // reverse or penetration service is still starting). Keep refreshing the
  // capability snapshot so a transient startup race does not leave the UI
  // permanently showing a module as unavailable.
  const refreshModules = useCallback(async () => {
    try {
      const data = await listModules()
      setModules(data.modules || [])
    } catch {
      // Keep the last known state while the API is temporarily unavailable.
    }
  }, [])

  const refreshSelected = useCallback(async (requestedId = selectedId) => {
    const runId = requestedId
    if (!runId) return
    // A full ledger can contain thousands of events and take longer than the
    // polling interval. Reuse the active request for the same run so timer,
    // websocket and manual refreshes cannot continuously invalidate each
    // other and leave the centre panel without a loaded run.
    if (runId !== selectedIdRef.current) return
    if (refreshRequest.current.runId === runId && refreshRequest.current.promise
      && refreshRequest.current.token === refreshToken.current) {
      return refreshRequest.current.promise
    }
    const token = ++refreshToken.current
    const isCurrent = () => token === refreshToken.current && runId === selectedIdRef.current
    const request = (async () => {
      // Start both requests together, but render the lightweight run summary
      // as soon as it arrives instead of blocking the whole page on a large
      // ledger response.
      const runPromise = getRun(runId)
      const afterSequence = ledgerCursor.current.runId === runId ? ledgerCursor.current.sequence : 0
      const ledgerPromise = getLedger(runId, afterSequence).then(
        (value) => ({ value, error: null }),
        (error) => ({ value: null, error }),
      )
      let nextRun
      try {
        nextRun = await runPromise
      } catch (error) {
        if (!isCurrent()) return
        throw error
      }
      if (!isCurrent()) return
      setRun(nextRun)
      if (['completed', 'partial', 'failed', 'denied'].includes(nextRun.status)
        && reportFailedRun.current !== runId && !reportRefreshInFlight.current) {
        setReportRead(current => current.runId === runId && current.status === 'ready' ? current : { runId, status: 'loading', error: '' })
      }

      const ledgerResult = await ledgerPromise
      if (!isCurrent()) return
      // The run summary is authoritative for status. A ledger read can fail
      // independently (large file, temporary lock, or a reconnect race); in
      // that case keep the last known events and still refresh the report.
      if (!ledgerResult.error) {
        const ledgerEvents = ledgerResult.value.events || []
        const sequence = ledgerEvents.reduce((cursor, event) => Math.max(cursor, event.sequence || 0), afterSequence)
        ledgerCursor.current = { runId, sequence }
        lastSequence.current = Math.max(lastSequence.current, sequence)
        if (ledgerEvents.length) setEvents((current) => mergeLedgerEvents(ledgerEvents, current))
      }
      // A report is a terminal artifact.  Avoid repeatedly requesting a 409
      // while the exploration path is still running, and never present an
      // early/partial report as the final result.
      const terminal = ['completed', 'partial', 'failed', 'denied'].includes(nextRun.status)
      if (terminal) {
        if (reportFailedRun.current !== runId && !reportRefreshInFlight.current) await readReport(runId)
      } else if (isCurrent()) {
        setReport(null)
        setSelectedEvidence(null)
        if (!reportRefreshInFlight.current) {
          reportReadSequence.current += 1
          reportReadRequest.current = null
          setReportReading(false)
        }
        if (reportFailedRun.current !== runId) setReportRead({ runId, status: 'idle', error: '' })
      }
      return nextRun
    })()
    refreshRequest.current = { runId, promise: request, token }
    try {
      return await request
    } finally {
      if (refreshRequest.current.promise === request) {
        refreshRequest.current = { runId: '', promise: null }
      }
    }
  }, [selectedId, readReport])

  const clearMissingRun = useCallback(async (missingId) => {
    if (selectedIdRef.current !== missingId) return
    socketRef.current?.close()
    setRun(null)
    setEvents([])
    setReport(null)
    setSelectedId('')
    const params = new URLSearchParams(location.search)
    params.delete('run')
    navigate({ pathname: location.pathname, search: params.toString() }, { replace: true })
    await refreshRuns(true)
  }, [location.pathname, location.search, navigate, refreshRuns])

  useEffect(() => {
    refreshRuns().catch((error) => message.error(error.message))
    return () => { runsRequestSequence.current += 1; runsRequest.current = null }
  }, [refreshRuns, message])
  useEffect(() => {
    refreshModules()
    const timer = setInterval(refreshModules, 10000)
    return () => clearInterval(timer)
  }, [refreshModules])
  useEffect(() => {
    const params = new URLSearchParams(location.search)
    if (params.get('create') === '1') setModalOpen(true)
    if (params.get('view') === 'result') setView('result')
    setSelectedId(params.get('run') || '')
    batchIdRef.current = params.get('batch') || ''
    setBatchId(batchIdRef.current)
  }, [location.search])
  useEffect(() => {
    refreshToken.current += 1
    setRun(null); setEvents([]); setReport(null)
    reportReadSequence.current += 1
    reportReadRequest.current = null
    reportFailedRun.current = ''
    setReportRead({ runId: selectedId, status: 'idle', error: '' })
    setReportReading(false)
    setRefreshingReport(false)
    setSelectedEvidence(null)
    lastSequence.current = 0
    ledgerCursor.current = { runId: selectedId, sequence: 0 }
    assetRequestToken.current += 1
    setAssetDrawerOpen(false); setAssetRunId(''); setAssetExperiences([]); setAssetLoading(false)
    return () => { reportReadSequence.current += 1 }
  }, [selectedId])

  useEffect(() => {
    if (!selectedId) return undefined
    refreshSelected().catch((error) => {
      if (error.status === 404) {
        clearMissingRun(selectedId).catch(() => {})
        return
      }
      message.error(`读取任务失败：${error.message}`)
    })
    const timer = setInterval(() => {
      refreshSelected().catch(() => {})
      refreshRuns().catch(() => {})
    }, ['completed', 'partial', 'failed', 'denied'].includes(run?.status) ? 6000 : 1500)
    return () => clearInterval(timer)
  }, [selectedId, run?.status, refreshSelected, clearMissingRun])

  useEffect(() => {
    socketRef.current?.close()
    if (!selectedId || run?.run_id !== selectedId) return undefined
    let disposed = false
    let reconnectTimer
    const connect = () => {
      if (disposed) return
      const socket = new WebSocket(eventSocketUrl(selectedId, lastSequence.current))
      socketRef.current = socket
      socket.onopen = () => setStreamConnected(true)
      socket.onmessage = ({ data }) => {
        if (disposed || selectedIdRef.current !== selectedId) return
        try {
          const event = JSON.parse(data)
          lastSequence.current = Math.max(lastSequence.current, event.sequence || 0)
          setEvents((current) => current.some((item) => item.event_id === event.event_id || item.sequence === event.sequence)
            ? current : [...current, event].sort((a, b) => a.sequence - b.sequence))
          if ([
            'agent.completed', 'agent.failed', 'tool.started', 'tool.completed',
            'analysis.completed', 'verification.completed', 'report.generated', 'report.refreshed',
            'run.failed', 'penetration.status', 'penetration.terminal',
            'approval.requested', 'approval.resolved', 'approval.failed',
            'exploration.updated', 'exploration.completed',
          ].includes(event.event_type)) {
            refreshSelected().catch(() => {})
          }
        } catch { message.error('收到无法解析的实时事件') }
      }
      socket.onclose = () => {
        setStreamConnected(false)
        if (!disposed) reconnectTimer = window.setTimeout(connect, 1200)
      }
      socket.onerror = () => setStreamConnected(false)
    }
    connect()
    return () => {
      disposed = true
      window.clearTimeout(reconnectTimer)
      socketRef.current?.close()
      setStreamConnected(false)
    }
  }, [selectedId, run?.run_id])

  const network = useMemo(() => deriveNetwork(events, run?.status), [events, run?.status])
  const isGraphView = view === 'graph' || view === 'coverage'
  const currentReport = report?.run_id === selectedId && run?.run_id === selectedId
    && ['completed', 'partial', 'failed', 'denied'].includes(run.status)
    && reportRead.runId === selectedId && reportRead.status === 'ready' ? report : null

  /** @param {string} evidenceId */
  function selectEvidence(evidenceId) {
    if (!currentReport || currentReport.run_id !== selectedIdRef.current) return
    setSelectedEvidence({ runId: currentReport.run_id, evidenceId })
  }

  async function retryReportRead() {
    const runId = selectedIdRef.current
    if (!runId || run?.run_id !== runId || reportReadRequest.current || reportRefreshInFlight.current) return
    await readReport(runId)
  }

  useEffect(() => {
    if (!approvalQueued) return
    if (run?.run_id !== approvalQueued.runId || run?.status !== 'waiting_approval'
      || run?.pending_approval?.request_id !== approvalQueued.requestId
      || events.some((event) => event.event_type === 'approval.failed' && event.sequence > approvalQueued.afterSequence)) {
      setApprovalQueued(null)
    }
  }, [approvalQueued, run?.run_id, run?.status, run?.pending_approval?.request_id, events])

  useEffect(() => { setApprovalError('') }, [selectedId])

  async function approval(decision) {
    const pending = run?.pending_approval
    if (!pending || approvalInFlight.current || approvalQueued?.requestId === pending.request_id) return
    approvalInFlight.current = true
    setApprovalBusy(true)
    setApprovalError('')
    const afterSequence = lastSequence.current
    try {
      await submitApproval(run.run_id, pending.request_id, { decision, actor: 'web-operator', reason: `operator ${decision}` })
      setApprovalQueued({ runId: run.run_id, requestId: pending.request_id, afterSequence })
      message.info(decision === 'approve' ? '批准已提交，任务正在继续执行' : '拒绝已提交，正在更新任务状态')
      await Promise.allSettled([refreshSelected(run.run_id), refreshRuns(true)])
    } catch (error) {
      setApprovalError(error.status === 409 ? '审批请求已变化或正在处理，请查看刷新后的任务状态。' : `审批提交失败：${error.message}`)
      message.error(error.status === 409 ? '审批请求已变化或正在处理' : `审批提交失败：${error.message}`)
      refreshSelected(run.run_id).catch(() => {})
    } finally {
      approvalInFlight.current = false
      setApprovalBusy(false)
    }
  }

  async function decideMcp(item, decision) {
    if (mcpApprovalInFlight.current || !run || run.run_id !== selectedIdRef.current
      || !run.mcp_pending_approvals?.some((pending) => pending.approval_id === item.approval_id)) return
    const runId = run.run_id
    mcpApprovalInFlight.current = true
    setMcpApprovalBusy(item.approval_id)
    try {
      await decideMcpApproval(item.approval_id, decision)
      message.success(decision === 'approve' ? '已批准本次调用' : '已拒绝本次调用')
      await refreshSelected(runId)
    } catch (error) {
      message.error(`MCP 审批失败：${error.message}`)
      await refreshSelected(runId).catch(() => {})
    } finally {
      mcpApprovalInFlight.current = false
      setMcpApprovalBusy('')
    }
  }

  async function openAssetDrawer() {
    const runId = run?.run_id
    if (!runId || runId !== selectedIdRef.current) return
    const token = ++assetRequestToken.current
    setAssetRunId(runId)
    setAssetExperiences([])
    setAssetDrawerOpen(true)
    setAssetLoading(true)
    try {
      const data = await getRunExperienceUses(runId)
      if (token !== assetRequestToken.current || runId !== selectedIdRef.current) return
      setAssetExperiences((data.uses || []).map(use => ({ ...JSON.parse(use.context_snapshot), model_cited: use.model_cited })))
    } catch (error) {
      if (token !== assetRequestToken.current || runId !== selectedIdRef.current) return
      setAssetExperiences([])
      message.warning(`经验接口暂不可用：${error.message}`)
    } finally {
      if (token === assetRequestToken.current && runId === selectedIdRef.current) setAssetLoading(false)
    }
  }

  async function refreshLatestResult() {
    const runId = selectedIdRef.current
    const selected = run?.run_id === runId ? run : runs.find((item) => item.run_id === runId)
    if (reportRefreshInFlight.current || reportReadRequest.current || !runId
      || !['penetration', 'code_audit', 'reverse', 'log_analysis'].includes(selected?.module_route)) return
    const sequence = ++reportReadSequence.current
    const isCurrent = () => sequence === reportReadSequence.current && runId === selectedIdRef.current
    const synchronizeReport = !['pending', 'running', 'waiting_approval'].includes(selected.status)
    reportRefreshInFlight.current = true
    setRefreshingReport(true)
    let reportSynced = false
    try {
      if (synchronizeReport) {
        setReport(null)
        setSelectedEvidence(null)
        reportFailedRun.current = ''
        setReportReading(true)
        setReportRead({ runId, status: 'loading', error: '' })
        const latestReport = await refreshRunReport(runId)
        if (!isCurrent()) return
        if (!latestReport || latestReport.run_id !== runId || typeof latestReport.executive_summary !== 'string') {
          throw new TypeError(`任务 ${runId} 返回了不匹配或缺少摘要的报告；请重新读取`)
        }
        reportSynced = true
        setReport(latestReport)
        setReportRead({ runId, status: 'ready', error: '' })
      }
      const refreshed = await refreshSelected(runId)
      if (!isCurrent()) return
      if (!refreshed) throw new Error('任务状态暂未刷新')
      try { await refreshRuns() }
      catch (error) { if (isCurrent()) message.warning(`任务已刷新，任务列表暂未更新：${error.message}`); return }
      if (isCurrent()) message.success(reportSynced ? '报告和任务状态已同步' : '任务状态已刷新')
    } catch (error) {
      if (!isCurrent()) return
      if (!(error instanceof Error)) throw error
      if (reportSynced) message.warning(`报告已同步，任务状态暂未刷新：${error.message}`)
      else {
        if (synchronizeReport) recordReportFailure(error, runId, 'POST')
        message.error(`同步最新内容失败：${error.message}`)
      }
    } finally {
      reportRefreshInFlight.current = false
      if (isCurrent()) {
        setRefreshingReport(false)
        setReportReading(false)
      }
    }
  }

  async function created({ runId, batchId }) {
    setRun(null); setEvents([]); setReport(null)
    lastSequence.current = 0
    ledgerCursor.current = { runId: runId || '', sequence: 0 }
    if (batchId) {
      batchIdRef.current = batchId
      setBatchId(batchId)
      setBatch(null)
      selectedIdRef.current = runId || ''
      setSelectedId(runId || '')
      navigate(`/workbench?batch=${encodeURIComponent(batchId)}${runId ? `&run=${encodeURIComponent(runId)}` : ''}`, { replace: true })
    }
    if (runId) {
      selectedIdRef.current = runId
      setSelectedId(runId); setView('stream')
      if (!batchId) navigate(`/workbench?run=${encodeURIComponent(runId)}`, { replace: true })
    }
    try {
      await refreshRuns(true)
    } catch (error) {
      message.warning(`任务已创建，任务列表暂未刷新：${error.message}`)
    }
    // The run can be visible in the list a moment before its state is
    // readable by the detail endpoint. Load the newly created ID explicitly
    // and retry briefly so the central panel does not remain on "waiting".
    if (runId) {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          await refreshSelected(runId)
          break
        } catch (error) {
          if (error.status !== 404 || attempt === 2) break
          await new Promise((resolve) => window.setTimeout(resolve, 400))
        }
      }
    }
    setModalOpen(false)
    message.success(batchId ? `批次 ${compactId(batchId)} 已创建，题目正在分批执行` : `任务 ${compactId(runId)} 已进入执行队列`)
  }

  async function openRetry() {
    if (!run?.can_retry || run.run_id !== selectedId) return
    const source = run
    let config
    try { config = await getTaskBudgetDefaults() } catch (error) {
      message.error(`读取探索预算失败：${error.message}`)
      return
    }
    if (selectedIdRef.current !== source.run_id) return
    setRetryBudget(retryTaskBudget(source, config))
    setRetryBudgetLimits(config.limits)
    setRetryNetworkPolicy('inherit')
    if (retryRequest.current?.runId !== run.run_id) {
      retryRequest.current = { runId: run.run_id, requestId: crypto.randomUUID() }
    }
    setRetrySource(source)
  }

  async function startRetry() {
    if (!retrySource || retrying || !validTaskBudget(retryBudget, retryBudgetLimits)) return
    setRetrying(true)
    try {
      const parameters = {
        ...retryBudget,
        ...(retryNetworkPolicy === 'inherit' ? {} : { network_policy: retryNetworkPolicy }),
      }
      const payloadKey = JSON.stringify(parameters)
      if (retryRequest.current?.runId !== retrySource.run_id ||
          (retryRequest.current.payloadKey && retryRequest.current.payloadKey !== payloadKey)) {
        retryRequest.current = { runId: retrySource.run_id, requestId: crypto.randomUUID() }
      }
      retryRequest.current.payloadKey = payloadKey
      const result = await retryRun(retrySource.run_id, {
        request_id: retryRequest.current.requestId, ...parameters,
      })
      setRetrySource(null)
      retryRequest.current = null
      await created({ runId: result.run_id })
    } catch (error) {
      message.error(`重试未能提交：${error.message}`)
    } finally {
      setRetrying(false)
    }
  }

  async function stopCurrentRun() {
    if (!run || cancelling) return
    setCancelling(true)
    try {
      await cancelRun(run.run_id)
      message.success('终止请求已提交')
      await Promise.allSettled([refreshSelected(run.run_id), refreshRuns(true)])
    } catch (error) {
      message.error(`终止任务失败：${error.message}`)
    } finally {
      setCancelling(false)
    }
  }

  return <div className="workbench-grid">
    <TaskSettingsDrawer open={Boolean(settingsRunId)} runId={settingsRunId} onClose={() => setSettingsRunId('')} onSaved={(updated) => {
      setSettingsRunId('')
      setRuns((current) => current.map((item) => item.run_id === updated.run_id ? { ...item, name: updated.name } : item))
      if (selectedIdRef.current === updated.run_id) setRun((current) => current ? { ...current, name: updated.name } : current)
      message.success('任务设置已保存，后续调用将实时采用新配置')
    }} onDeleted={(deletedId) => {
      setSettingsRunId('')
      const remaining = runs.filter((item) => item.run_id !== deletedId)
      setRuns((current) => current.filter((item) => item.run_id !== deletedId))
      setRunsTotal((current) => Math.max(0, current - 1))
      runsCursor.current = null
      if (selectedIdRef.current === deletedId) {
        const nextId = remaining[0]?.run_id || ''
        selectedIdRef.current = nextId
        setSelectedId(nextId)
        setRun(null); setEvents([]); setReport(null)
        const params = new URLSearchParams(location.search)
        if (nextId) params.set('run', nextId)
        else params.delete('run')
        navigate({ pathname: location.pathname, search: params.toString() }, { replace: true })
      }
      refreshRuns(true).catch((error) => message.warning(`任务已删除，列表刷新失败：${error.message}`))
      message.success('任务已删除')
    }} />
    <Modal title="重试任务" open={Boolean(retrySource)} onCancel={() => !retrying && setRetrySource(null)} onOk={startRetry} okText="开始重试" cancelText="取消" confirmLoading={retrying} cancelButtonProps={{ disabled: retrying }} okButtonProps={{ disabled: !validTaskBudget(retryBudget, retryBudgetLimits) }}>
      <p>使用原任务的材料、目标和授权范围创建新任务，并参考上次失败原因重新规划。原记录与证据会保留；本次会重新执行并产生新的用量。</p>
      {retrySource?.stop_reason && <Alert type="warning" showIcon title="上次停止原因" description={retrySource.stop_reason} />}
      {retryBudget && <TaskBudgetFields budget={retryBudget} limits={retryBudgetLimits} onChange={setRetryBudget} disabled={retrying} />}
      {retrySource?.module_route === 'penetration' && <p><label htmlFor="retry-network-policy">网络访问范围</label><br /><Select disabled={retrying} id="retry-network-policy" style={{ width: '100%' }} value={retryNetworkPolicy} onChange={setRetryNetworkPolicy} options={[
        { value: 'inherit', label: '沿用原任务策略（默认）' },
        ...networkPolicyOptions(),
      ]} /><small>选择其他策略会改变本次重试允许的网络操作，请核对目标授权。</small></p>}
    </Modal>
    <TaskModal open={modalOpen} onClose={() => setModalOpen(false)} onCreated={created} />
    <AssetUsageDrawer open={assetDrawerOpen && assetRunId === selectedId && run?.run_id === assetRunId} onClose={() => { assetRequestToken.current += 1; setAssetDrawerOpen(false); setAssetLoading(false) }} loading={assetLoading} events={events} experiences={assetExperiences} run={run} />
    <aside className={`glass-panel session-panel ${isGraphView ? 'is-graph-hidden' : ''}`}>
      <div className="panel-heading"><div><Text className="panel-kicker">RUNS</Text><Title level={4}>任务流程</Title></div><Button type="text" icon={<ReloadOutlined />} onClick={() => refreshRuns(true)} /></div>
      <Button type="primary" icon={<PlusOutlined />} block onClick={() => setModalOpen(true)}>新建任务</Button>
      {batchId && <section className="batch-summary" style={{ marginTop: 16 }}>
        <Space><Text strong>题库批次 {compactId(batchId)}</Text><Button size="small" onClick={() => { batchIdRef.current = ''; setBatchId(''); setBatch(null); navigate('/workbench', { replace: true }) }}>关闭</Button></Space>
        {batchError && <Alert type="error" showIcon title={`批次读取失败：${batchError}`} />}
        {batch && <><p><Tag color={['completed'].includes(batch.status) ? 'success' : ['failed', 'partial_failed'].includes(batch.status) ? 'warning' : 'processing'}>{({ dispatching: '分发中', running: '运行中', completed: '已完成', partial_failed: '部分失败', failed: '失败' })[batch.status] || batch.status}</Tag>共 {batch.tasks?.length || 0} 道题</p>
          {(batch.tasks || []).map(item => <div key={item.task_id} style={{ margin: '8px 0' }}><Button size="small" type="link" disabled={!item.run_id} onClick={() => { selectedIdRef.current = item.run_id; setSelectedId(item.run_id); navigate(`/workbench?batch=${encodeURIComponent(batchId)}&run=${encodeURIComponent(item.run_id)}`, { replace: true }) }}>{item.name || item.task_id}</Button><Tag>{({ pending: '等待分发', queued: '排队中', running: '运行中', succeeded: '已完成', partial: '部分完成', denied: '已拒绝', failed: '失败', blocked: '依赖阻断', cancelled: '已取消' })[item.status] || item.status}</Tag>{item.error && <Text type="danger">{item.error}</Text>}</div>)}
        </>}
      </section>}
      <div className="session-list">{runs.length ? runs.map((item) => <div className={`session-item-row ${selectedId === item.run_id ? 'is-active' : ''}`} key={item.run_id}>
        <button type="button" className={`session-item ${selectedId === item.run_id ? 'is-active' : ''}`} onClick={() => { selectedIdRef.current = item.run_id; setSelectedId(item.run_id); navigate(`/workbench?${batchId ? `batch=${encodeURIComponent(batchId)}&` : ''}run=${encodeURIComponent(item.run_id)}`, { replace: true }) }}>
          <span><b>{item.name || (item.scenario === 'unknown' ? '等待场景识别' : item.scenario)}</b><small>{item.name && item.scenario !== 'unknown' ? `${item.scenario} · ` : ''}{compactId(item.run_id)}</small><em className="session-usage">{usageCaption(item)}</em></span><StatusTag status={item.status} />
        </button>
        <Tooltip title="查看并编辑任务详情"><Button type="text" size="small" aria-label={`编辑任务 ${item.name || compactId(item.run_id)}`} icon={<EditOutlined />} onClick={() => setSettingsRunId(item.run_id)} /></Tooltip>
      </div>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无任务" />}</div>
      {runsHasMore && <Button block loading={runsLoadingMore} onClick={async () => { setRunsLoadingMore(true); try { const data = await listRuns({ before: runsCursor.current, limit: 100 }); runsCursor.current = data.next_cursor; setRunsTotal(data.total ?? 0); setRuns(current => { const seen = new Set(current.map(item => item.run_id)); return [...current, ...(data.runs || []).filter(item => !seen.has(item.run_id))] }) } catch (error) { message.error(`加载任务失败：${error.message}`) } finally { setRunsLoadingMore(false) } }}>加载更多任务</Button>}
    </aside>

    <section className={`glass-panel conversation-panel ${isGraphView ? 'is-graph' : ''}`}>
      <div className="run-heading">
        <div className="run-heading-top">
          <div className="run-heading-title">
            <Text className="panel-kicker">当前任务</Text>
            <div className="run-heading-name"><Title level={4} title={run?.name || run?.scenario || '实时协作等待任务'}>{run ? run.name || run.scenario : '实时协作等待任务'}</Title>{run && <Tooltip title="查看并编辑任务详情"><Button type="text" size="small" aria-label="编辑当前任务" icon={<EditOutlined />} onClick={() => setSettingsRunId(run.run_id)} /></Tooltip>}</div>
            {run && <span className="run-heading-id" title={run.run_id}>任务编号 · {compactId(run.run_id)}</span>}
          </div>
          <div className="run-heading-primary">
            {run && <StatusTag status={run.status} />}
            <Button size="small" type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新建任务</Button>
          </div>
        </div>
        <div className="run-view-tabs" role="group" aria-label="任务视图">
        <Segmented size="small" value={view} onChange={setView} options={[
          { value: 'stream', label: 'AI 实时流', icon: <TeamOutlined /> },
          { value: 'graph', label: <span data-testid="workbench-view-graph">探索路径</span>, icon: <BranchesOutlined /> },
          { value: 'coverage', label: '资产引用图', icon: <DeploymentUnitOutlined /> },
          { value: 'thinking', label: '执行摘要', icon: <AuditOutlined /> },
          { value: 'result', label: '任务结果', icon: <FileTextOutlined /> },
        ]} />
        </div>
        <div className="run-heading-actions">
        {run?.run_id === selectedId && ['pending', 'running', 'waiting_approval'].includes(run.status) && <Button size="small" danger loading={cancelling} onClick={() => Modal.confirm({ title: '终止当前任务？', content: '终止后会停止后续执行，并保留当前账本与黑板记录。', okText: '终止任务', cancelText: '继续运行', okButtonProps: { danger: true }, onOk: stopCurrentRun })}>终止任务</Button>}
        {run?.run_id === selectedId && ['partial', 'failed'].includes(run.status) && <Tooltip title={run.can_retry ? '保留原记录，重新规划并执行' : run.retry_blocked_reason}><span><Button aria-label="重试任务" size="small" type="primary" icon={<ReloadOutlined />} disabled={!run.can_retry} loading={retrying} onClick={openRetry}>重试任务</Button></span></Tooltip>}
        {['penetration', 'code_audit', 'reverse', 'log_analysis'].includes(run?.module_route || runs.find((item) => item.run_id === selectedId)?.module_route) && <Button size="small" icon={<ReloadOutlined />} data-testid="report-refresh-latest" aria-label="刷新最新内容" loading={refreshingReport} disabled={reportReading} onClick={refreshLatestResult}>刷新最新内容</Button>}
        <Button size="small" icon={<DatabaseOutlined />} data-testid="task-assets-open" aria-label="查看任务资产调用" disabled={!run || run.run_id !== selectedId} onClick={openAssetDrawer}>资产调用</Button>
        <Button type="text" title="打开审计回放" icon={<AuditOutlined />} onClick={() => navigate(selectedId ? `/audit/${selectedId}` : '/audit')} />
        </div>
      </div>
      {view !== 'graph' && <><div className="collaboration-strip">{network.roles.map((role, index) => <React.Fragment key={role.id}>{index > 0 && <span>→</span>}<span className={`is-${role.status}`}>{role.shortName}</span></React.Fragment>)}</div>
      <ModuleFlow run={run} events={events} /></>}
      {run?.run_id === selectedId && run.stop_reason && <Alert type="warning" showIcon title="任务未完成" description={<div style={{ overflowWrap: 'anywhere' }}>{localizePublicText(run.stop_reason)}{!run.can_retry && run.retry_blocked_reason && <p>{run.retry_blocked_reason}</p>}</div>} />}
      {run?.run_id === selectedId && run.retry_of && <Button type="link" onClick={() => navigate(`/workbench?run=${encodeURIComponent(run.retry_of)}`)}>查看重试来源任务</Button>}
      {run?.run_id === selectedId && run?.status === 'waiting_approval' && run.pending_approval && <Alert className="approval-alert" type="warning" showIcon title={`步骤 ${run.pending_approval.step_id} 等待审批`} description={<div>
        <p>申请类型：{run.pending_approval.reason.includes('授权') || run.pending_approval.reason.includes('范围') ? '授权范围例外' : `R${run.pending_approval.risk_level} 工具调用`}</p>
        <p>工具：{run.pending_approval.tool_name} · 目标：{run.pending_approval.target} · 风险：R{run.pending_approval.risk_level}</p>
        <p>申请原因：{run.pending_approval.reason}</p>
        <p>预期影响：{run.pending_approval.expected_impact}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 320, overflowY: 'auto' }}>{JSON.stringify(run.pending_approval.parameters, null, 2)}</pre>
        <Space><Button type="primary" loading={approvalBusy} disabled={Boolean(approvalQueued)} onClick={() => approval('approve')}>批准</Button><Button danger disabled={approvalBusy || Boolean(approvalQueued)} onClick={() => approval('deny')}>拒绝</Button></Space>
        {approvalQueued?.runId === run.run_id && approvalQueued.requestId === run.pending_approval.request_id && <p role="status">审批已提交，正在等待任务更新。</p>}
        {(approvalError || run.last_error?.startsWith('审批暂未完成')) && <p role="alert">{approvalError || run.last_error}</p>}
      </div>} />}
      {run?.run_id === selectedId && run.mcp_pending_approvals?.map((item) => <Alert key={item.approval_id} className="approval-alert" type="warning" showIcon title={`MCP 调用待审批：${item.server_id} / ${item.tool_name}`} description={<div>
        <p>申请类型：{item.approval_type || '逐次工具调用'}</p>
        <p>目标：{item.target || '未指定'} · 风险：{item.risk_level}</p>
        {item.policy_reasons?.length > 0 && <p>超出预设范围：{item.policy_reasons.join('；')}</p>}
        <p>预期影响：{item.expected_impact}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 320, overflowY: 'auto' }}>{JSON.stringify(item.arguments, null, 2)}</pre>
        <Space><Button type="primary" loading={mcpApprovalBusy === item.approval_id} disabled={Boolean(mcpApprovalBusy)} onClick={() => decideMcp(item, 'approve')}>批准本次调用</Button><Button danger disabled={Boolean(mcpApprovalBusy)} onClick={() => decideMcp(item, 'deny')}>拒绝</Button></Space>
      </div>} />)}
      {view === 'stream' ? <RuntimeStream events={events} connected={streamConnected} active={Boolean(run?.run_id && run.run_id === selectedId)} /> : view === 'graph' ? <BlackboardGraph run={run} events={events} /> : view === 'coverage' ? <AssetCoverageGraph run={run} /> : view === 'thinking' ? <AIThoughtTimeline events={events} runStatus={run?.status} downloadUrl={run ? thoughtProcessUrl(run.run_id) : ''} /> : currentReport ? <div className="report-view">
        <EvidenceDrawer key={selectedId} open={selectedEvidence?.runId === selectedId} evidenceId={selectedEvidence?.evidenceId || null} report={currentReport} onClose={() => setSelectedEvidence(null)} />
        <div className="report-hero"><Space wrap><Text className="panel-kicker">安全分析报告</Text><ReportExportButtons key={selectedId} report={currentReport} run={run} /></Space><Title level={3}>{localizePublicText(report.executive_summary)}</Title><RetestConclusion runId={run.run_id} section="executive_summary" index={0} text={report.executive_summary} moduleRoute={run.module_route} originalEvidence={(report.evidence || []).map(item => item.evidence_id)} /><Paragraph>{report.limitations?.map(localizePublicText).join('；') || '查看各项结论的验证状态与证据。'}</Paragraph></div>
        <LogAnalysisPanel key={run.run_id} value={report.log_analysis} onEvidenceSelect={selectEvidence} />
        {getVerifiedOutputs(report).length > 0 && <section className="verified-output-list" aria-label="已验证输出">
          {getVerifiedOutputs(report).map((value) => <article className="verified-output" key={value}>
            <div><Text className="panel-kicker">已获取 Flag</Text><code>{value}</code><RetestConclusion runId={run.run_id} section="verified_outputs" index={report.verified_outputs?.indexOf(value) ?? -1} text={value} moduleRoute={run.module_route} originalEvidence={(report.evidence || []).map(item => item.evidence_id)} /></div>
            <Button aria-label="复制 Flag" title="复制 Flag" icon={<CopyOutlined />} onClick={() => copyOutput(value)} />
          </article>)}
        </section>}
        {(run?.external_execution?.blackboard?.planning_mode === 'workbench'
          ? [['已确认发现', report.confirmed_findings], ['待验证候选', report.candidate_findings]]
          : [['发现与证据', report.findings]]).map(([label, findings]) => <section key={label} aria-label={label}>
          <Title level={4}>{label} · {findings?.length || 0}</Title>
          {findings?.map(localizeFinding).map((finding) => <article className="finding-card" key={finding.finding_id}><span className={`severity is-${finding.severity.toLowerCase()}`}>{severityLabels[finding.severity] || finding.severity}</span><div><b>{finding.title}</b><p>{finding.description}</p>{finding.remediation && <p className="finding-remediation"><strong>修复建议：</strong>{finding.remediation}</p>}<small>{finding.path}{finding.line ? `:${finding.line}` : ''} · 证据 {finding.evidence_ids?.length ? finding.evidence_ids.map((id, index) => <Button type="link" size="small" key={`${id}:${index}`} data-testid="report-evidence-reference" data-evidence-id={id} aria-label={`查看证据 ${id}`} onClick={() => selectEvidence(id)}>{id}</Button>) : '暂无有效证据'}</small><TrafficEvidencePanel runId={run.run_id} finding={finding} events={events} evidence={report.evidence} onChanged={() => refreshSelected(run.run_id)} /><RetestPanel runId={run.run_id} kind="finding" reference={finding.finding_id} conclusion={finding.title} moduleRoute={run.module_route} originalEvidence={finding.evidence_ids} /></div></article>)}
        </section>)}
        {report.evidence?.length > 0 && <section aria-label="报告证据索引" data-testid="report-evidence-index"><Title level={4}>证据索引 · {report.evidence.length}</Title><Space wrap>{report.evidence.map((item, index) => <Button type="link" size="small" key={`${item.evidence_id}:${index}`} data-testid="report-evidence-reference" data-evidence-id={item.evidence_id} aria-label={`查看证据 ${item.evidence_id}`} onClick={() => selectEvidence(item.evidence_id)}>{item.evidence_id}</Button>)}</Space></section>}
        {[['已排除方向', 'ruled_out_directions', report.ruled_out_directions], ['证据不足', 'insufficient_evidence', report.insufficient_evidence], ['Worker 报告', 'worker_reports', report.worker_reports], ['执行限制', 'limitations', report.limitations]].map(([label, section, items]) => items?.length > 0 && <section key={label} aria-label={label}><Title level={4}>{label} · {items.length}</Title><ul>{items.map((item, index) => <li key={index}>{localizePublicText(item)} <RetestConclusion runId={run.run_id} section={section} index={index} text={item} moduleRoute={run.module_route} originalEvidence={(report.evidence || []).map(evidence => evidence.evidence_id)} /></li>)}</ul></section>)}
        {report.retests?.length > 0 && <section aria-label="独立复核记录"><Title level={4}>独立复核 · {report.retests.length}</Title>
          {report.retests.map(item => <div className="retest-report-row" key={item.retest_id}>
            <Tag>{item.verdict}</Tag><span>{item.summary}</span>
            <Text type="secondary">原对象 {item.source_kind}:{item.source_ref} · 原证据 {(item.original_evidence_ids || []).join('、') || '无'} · 本次证据 {(item.evidence_ids || []).join('、') || '无'}</Text>
            <Button size="small" icon={<LinkOutlined />} onClick={() => navigate(`/workbench?run=${encodeURIComponent(item.child_run_id)}`)}>查看复核任务</Button>
          </div>)}
        </section>}
      </div> : reportRead.runId === selectedId && reportRead.status === 'error' ? <Alert type="error" showIcon role="alert" data-testid="report-load-error" title="报告读取失败" description={reportRead.error}
        action={<Button size="small" data-testid="report-read-retry" aria-label="重新读取报告" loading={reportReading} disabled={reportReading || refreshingReport || run?.run_id !== selectedId} onClick={retryReportRead}>重新读取报告</Button>} />
        : reportRead.runId === selectedId && reportRead.status === 'loading' ? <div role="status" data-testid="report-loading">正在读取报告…</div>
          : reportRead.runId === selectedId && reportRead.status === 'not_ready' ? <div data-testid="report-not-ready"><Empty description="报告尚未生成（HTTP 409）" /><Button size="small" data-testid="report-read-retry" aria-label="重新读取报告" disabled={reportReading || refreshingReport || run?.run_id !== selectedId} onClick={retryReportRead}>重新读取报告</Button></div>
            : <Empty description={run && !['completed', 'partial', 'failed', 'denied'].includes(run.status) ? '探索路径尚未完成，结果生成已延迟' : '报告将在运行结束后生成'} />}
    </section>

    <aside className={`glass-panel inspector-panel ${isGraphView ? 'is-graph-hidden' : ''}`}>
      <div className="panel-heading"><div><Text className="panel-kicker">TASK STATUS</Text><Title level={4}>任务状态与协作</Title></div><SafetyCertificateOutlined className="heading-icon" /></div>
      <TaskStatusPanel run={run} events={events} />
      {run?.run_id === selectedId && <SideQuestionPanel runId={run.run_id} />}
      <div className="inspector-divider"><TeamOutlined /> 智能体网络</div>
      <AgentNetwork network={network} eventCount={events.length} />
      <div className="inspector-divider">模块状态</div>
      <div className="module-status-list">{modules.map((module) => <div className="module-status" key={module.id}><span><i className={module.available || module.local_available ? 'status-dot is-on' : 'status-dot'} />{module.name}</span><small>{module.available ? '已就绪' : module.local_available ? '本地分析可用 · 外部引擎离线' : '不可用'}</small></div>)}</div>
    </aside>
  </div>
}
