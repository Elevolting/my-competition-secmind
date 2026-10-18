import React, { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiOutlined,
  BarChartOutlined,
  CheckCircleOutlined,
  DatabaseOutlined,
  KeyOutlined,
  ReloadOutlined,
  RobotOutlined,
  SaveOutlined,
} from '@ant-design/icons'
import { Alert, App, Button, Form, Input, InputNumber, Popconfirm, Progress, Segmented, Select, Skeleton, Statistic, Table, Tag, Typography } from 'antd'
import { getAvailableModels, getModelConfig, getModelUsage, modelUsageSocketUrl, testModelConfig, updateModelConfig, updateModelUsageQuota } from '../api.js'

import { ModelSeriesChart, UsageChart } from './ModelSeriesChart.jsx'
import './model-dashboard.css'

const { Text, Title } = Typography
const modelRules = [{ required: true, whitespace: true, message: '请输入模型 ID' }]

function ModelPicker({ models, value, onChange, ...props }) {
  const [search, setSearch] = useState('')
  const ids = [...new Set([...models, value].filter(Boolean))]
  const custom = search.trim()
  const options = ids.map(id => ({ value: id, label: id }))
  if (custom && !ids.includes(custom)) {
    options.push({ value: custom, label: `使用自定义模型：${custom}` })
  }
  return <Select
    {...props}
    value={value}
    onChange={next => { setSearch(''); onChange?.(next) }}
    options={options}
    showSearch={{
      searchValue: search,
      onSearch: setSearch,
      filterOption: (input, option) => option.value.toLowerCase().includes(input.trim().toLowerCase()),
    }}
    onOpenChange={() => setSearch('')}
    optionLabelProp="value"
    notFoundContent="输入模型 ID，或先获取模型列表"
    style={{ width: '100%' }}
  />
}

export function ModelUsagePage() {
  const { message } = App.useApp()
  const [form] = Form.useForm()
  const [config, setConfig] = useState(null)
  const [configError, setConfigError] = useState('')
  const [usage, setUsage] = useState(null)
  const [usageError, setUsageError] = useState('')
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [modelOptions, setModelOptions] = useState([])
  const [modelsLoading, setModelsLoading] = useState(false)
  const [usagePeriod, setUsagePeriod] = useState('daily')
  const [quotaDraft, setQuotaDraft] = useState(null)
  const [quotaSaving, setQuotaSaving] = useState(false)
  const [section, setSection] = useState('overview')
  const dirty = useRef(false)
  const quotaDirty = useRef(false)
  const usageSequence = useRef(0)
  const configSequence = useRef(0)
  const draftVersion = useRef(0)

  const load = useCallback(async () => {
    setLoading(true)
    const configToken = ++configSequence.current
    const usageToken = ++usageSequence.current
    try {
      const [configResult, usageResult] = await Promise.allSettled([getModelConfig(), getModelUsage()])
      if (configToken === configSequence.current) {
        if (configResult.status === 'fulfilled') {
          const nextConfig = configResult.value
          setConfig(nextConfig)
          setConfigError('')
          if (!dirty.current) form.setFieldsValue({
            base_url: nextConfig.base_url,
            api_key: '',
            planner_model: nextConfig.planner_model,
            worker_model: nextConfig.worker_model,
            fallback_model: nextConfig.fallback_model,
          })
        } else { setConfig(null); setConfigError(configResult.reason.message) }
      }
      if (usageToken === usageSequence.current) {
        if (usageResult.status === 'fulfilled') {
          setUsage(usageResult.value); setUsageError('')
          if (!quotaDirty.current) setQuotaDraft(usageResult.value.quota)
        } else { setUsage(null); setUsageError(usageResult.reason.message) }
      }
      return { configLoaded: configResult.status === 'fulfilled', usageLoaded: usageResult.status === 'fulfilled' }
    } finally {
      if (configToken === configSequence.current) setLoading(false)
    }
  }, [form])

  useEffect(() => { load() }, [load])
  const refreshUsage = useCallback(async () => {
    const sequence = ++usageSequence.current
    try {
      const nextUsage = await getModelUsage()
      if (sequence !== usageSequence.current) return
      setUsage(nextUsage)
      setUsageError('')
      if (!quotaDirty.current) setQuotaDraft(nextUsage.quota)
    } catch (error) {
      if (sequence !== usageSequence.current) return
      setUsage(null)
      setUsageError(error.message)
    }
  }, [message])

  useEffect(() => {
    let disposed = false
    let socket
    let reconnectTimer
    let refreshTimer
    const connect = () => {
      if (disposed) return
      socket = new WebSocket(modelUsageSocketUrl())
      socket.onopen = refreshUsage
      socket.onmessage = () => {
        if (!refreshTimer) refreshTimer = window.setTimeout(() => { refreshTimer = null; refreshUsage() }, 500)
      }
      socket.onclose = () => {
        if (!disposed) reconnectTimer = window.setTimeout(connect, 1500)
      }
    }
    connect()
    const polling = window.setInterval(refreshUsage, 15000)
    return () => {
      disposed = true
      window.clearTimeout(reconnectTimer)
      window.clearTimeout(refreshTimer)
      socket?.close()
      window.clearInterval(polling)
    }
  }, [refreshUsage])

  async function testConnection() {
    let values
    try { values = await form.validateFields(['base_url', 'api_key', 'planner_model', 'worker_model', 'fallback_model']) } catch { return }
    const version = draftVersion.current
    setTesting(true)
    setTestResult(null)
    try {
      const result = await testModelConfig({
        base_url: values.base_url.trim(),
        api_key: values.api_key?.trim() || null,
        planner_model: values.planner_model.trim(),
        worker_model: values.worker_model.trim(),
        fallback_model: values.fallback_model.trim(),
      })
      if (version !== draftVersion.current) return
      setTestResult(result)
      message.success(`推理测试成功，验证了 ${result.model_count} 个模型`)
    } catch (error) {
      if (version !== draftVersion.current) return
      setTestResult({ ok: false, error: error.message })
      message.error(`连接失败：${error.message}`)
    } finally {
      setTesting(false)
    }
  }

  async function fetchModels() {
    let values
    try { values = await form.validateFields(['base_url', 'api_key']) } catch { return }
    const version = draftVersion.current
    setModelsLoading(true)
    try {
      const result = await getAvailableModels({ base_url: values.base_url.trim(), api_key: values.api_key?.trim() || null })
      if (version !== draftVersion.current) return
      setModelOptions(result.models || [])
      message.success(`已获取 ${result.models?.length || 0} 个可用模型`)
    } catch (error) {
      if (version !== draftVersion.current) return
      setModelOptions([])
      message.error(`获取模型列表失败：${error.message}`)
    } finally {
      setModelsLoading(false)
    }
  }

  async function applyConfig() {
    let values
    try { values = await form.validateFields() } catch { return }
    setSaving(true)
    try {
      const saved = await updateModelConfig({
        base_url: values.base_url.trim(),
        api_key: values.api_key?.trim() || null,
        planner_model: values.planner_model.trim(),
        worker_model: values.worker_model.trim(),
        fallback_model: values.fallback_model.trim(),
      })
      setTestResult(null)
      dirty.current = false
      message.success('连接与模型路由已应用')
      setConfig((current) => ({ ...current, ...saved }))
      const refreshed = await load()
      if (!refreshed.configLoaded) message.warning('配置已应用，页面暂未重新读取配置')
      if (!refreshed.usageLoaded) message.warning('配置已应用，用量暂未刷新')
    } catch (error) {
      message.error(`应用失败：${error.message}`)
    } finally {
      setSaving(false)
    }
  }

  async function clearKey() {
    const baseUrl = config.base_url
    setSaving(true)
    try {
      const saved = await updateModelConfig({ base_url: baseUrl.trim(), clear_api_key: true })
      setTestResult(null)
      dirty.current = false
      setModelOptions([])
      message.success('API Key 已清除，运行时已切换为 Demo 模式')
      setConfig((current) => ({ ...current, ...saved }))
      const refreshed = await load()
      if (!refreshed.configLoaded) message.warning('密钥已清除，页面暂未重新读取配置')
      if (!refreshed.usageLoaded) message.warning('密钥已清除，用量暂未刷新')
    } catch (error) {
      message.error(error.message)
    } finally {
      setSaving(false)
    }
  }

  async function saveQuota() {
    setQuotaSaving(true)
    try {
      const result = await updateModelUsageQuota({
        hourly_tokens: Number(quotaDraft?.hourly || 0),
        daily_tokens: Number(quotaDraft?.daily || 0),
        monthly_tokens: Number(quotaDraft?.monthly || 0),
      })
      setQuotaDraft(result.quota)
      quotaDirty.current = false
      setUsage((current) => current ? { ...current, quota: result.quota } : current)
      message.success('预算提醒已保存，不会自动停止模型调用')
    } catch (error) {
      message.error(`额度保存失败：${error.message}`)
    } finally {
      setQuotaSaving(false)
    }
  }

  if (loading && !config) return <div className="glass-panel loading-panel"><Skeleton active /></div>

  return <div className="models-page">
    <div className="page-intro">
      <div>
        <Text className="panel-kicker">MODEL RUNTIME</Text>
        <Title level={2}>模型配置与用量</Title>
        <p>配置 OpenAI 兼容模型服务与模型路由，查看实际调用和用量回执。总览为全部历史，图表按所选时间范围统计。</p>
      </div>
      <div className="intro-tags">
        <Tag color={config?.api_key_configured ? 'success' : 'default'}>{!config ? '配置状态未知' : config.api_key_configured ? '密钥已配置' : '密钥未配置'}</Tag>
        {config?.demo_mode && <Tag color="gold">DEMO MODE</Tag>}
        <Button type="text" icon={<ReloadOutlined />} onClick={load}>刷新</Button>
      </div>
    </div>

    <div className="model-page-tabs">
      <Segmented value={section} onChange={setSection} options={[{ value: 'overview', label: '用量信息' }, { value: 'config', label: '连接与模型配置' }]} />
      <Text type="secondary">{section === 'overview' ? '本地账本中的真实 Provider 回执' : 'OpenAI 兼容接口与模型路由'}</Text>
    </div>

    {section === 'overview' && <section className="usage-overview-head usage-stat-grid" aria-label="全部历史用量">
      <Statistic title="本地回执累计 Token（全部历史）" value={usage?.token_usage_available ? usage.total_tokens : '—'} />
      <Statistic title="请求 / CLI 执行" value={usage?.model_call_count ?? '—'} />
      <Statistic title="RUNS" value={usage?.run_count ?? '—'} />
      <Statistic title="CACHE READ" value={usage?.token_usage_available ? usage.cache_read_tokens : '—'} />
    </section>}

    <div className={`model-grid ${section === 'overview' ? 'is-overview' : 'is-config'}`}>
      <section className="glass-panel model-config-card" hidden={section !== 'config'}>
        <Alert type="info" showIcon title="统一管理规划模型和 Pi Worker" description="规划模型用于主任务规划和 Pi 意图规划；工作模型用于主任务执行及 Pi 的 Bootstrap、Explore。两者共用本页的服务地址和密钥，可分别选择模型。保存后，Pi 从下一轮调度读取新配置，正在执行的任务继续使用原配置。连接测试验证 OpenAI 兼容接口；SecMind 分析引擎仍单独配置。已知 Token 汇总在本页，预算仅提醒。" />
        {configError && <Alert type="error" title="配置读取失败" description={configError} />}
        <div className="panel-heading">
          <div><Text className="panel-kicker">MODEL CONFIGURATION</Text><Title level={4}>运行时连接</Title></div>
          <ApiOutlined className="heading-icon accent-gold" />
        </div>
        <Form form={form} layout="vertical" disabled={!config || saving || testing || modelsLoading} className="model-config-form" onValuesChange={(changed) => { dirty.current = true; draftVersion.current += 1; setTestResult(null); if ('base_url' in changed || 'api_key' in changed) setModelOptions([]) }}>
          <Form.Item
            name="base_url"
            label="Base URL"
            rules={[{ required: true, message: '请输入 Base URL' }, { type: 'url', message: '请输入有效的 HTTP/HTTPS URL' }]}
            extra="填写 OpenAI 兼容接口根地址，通常以 /v1 结尾；更换地址需填写对应密钥。"
          >
            <Input prefix={<ApiOutlined />} placeholder="https://model-gateway.example/v1" autoComplete="url" />
          </Form.Item>
          <Form.Item
            name="api_key"
            label="API Key"
            rules={[{ min: 8, message: 'API Key 至少需要 8 个字符' }]}
            extra={config?.api_key_configured ? '后端已保存密钥，因此这里不回显。地址不变时留空保留；填写新值则替换。' : '密钥保存在本机后端，用于向指定模型服务认证；不写入浏览器存储。'}
          >
            <Input.Password prefix={<KeyOutlined />} placeholder={config?.api_key_configured ? '••••••••（留空保留）' : 'sk-...'} autoComplete="new-password" />
          </Form.Item>

          <div className="model-selector-heading">
            <span><RobotOutlined /> 模型路由</span>
            <div><small>输入服务商支持的准确模型 ID</small><Button type="link" size="small" loading={modelsLoading} onClick={fetchModels}>自动获取模型列表</Button></div>
          </div>
          {modelOptions.length > 0 && <div className="model-list-status"><CheckCircleOutlined /><span>已获取 {modelOptions.length} 个可用模型：{modelOptions.slice(0, 8).join('、')}{modelOptions.length > 8 ? '…' : ''}</span></div>}
          <div className="model-selector-grid">
            <Form.Item name="planner_model" label="规划模型" rules={modelRules}>
              <ModelPicker models={modelOptions} placeholder="搜索或输入规划模型 ID" />
            </Form.Item>
            <Form.Item name="worker_model" label="工作模型（主任务 / Pi 执行）" rules={modelRules}>
              <ModelPicker models={modelOptions} placeholder="搜索或输入工作模型 ID" />
            </Form.Item>
            <Form.Item name="fallback_model" label="回退模型" rules={modelRules}>
              <ModelPicker models={modelOptions} placeholder="搜索或输入回退模型 ID" />
            </Form.Item>
          </div>
          <div className="runtime-hint"><span>请求超时</span><b>{config?.timeout_seconds} 秒</b></div>

          <p>测试会实际请求所选模型生成短回复，相同模型只测一次，用量计入本地统计；不会保存草稿配置。</p>
          {testResult && <Alert className="connection-result" showIcon type={testResult.ok ? 'success' : 'error'} title={testResult.ok ? '模型推理测试通过' : '模型推理测试失败'} description={testResult.ok ? `验证 ${testResult.model_count} 个模型，总耗时 ${testResult.latency_ms} ms。` : testResult.error} />}
          <div className="config-actions">
            <Button icon={<ApiOutlined />} loading={testing} onClick={testConnection}>测试连接</Button>
            <Button type="primary" icon={<CheckCircleOutlined />} loading={saving} onClick={applyConfig}>应用配置</Button>
            {config?.api_key_configured && <Popconfirm title="确认清除 API Key？" description="清除后将立即切换为 Demo 模式。" okText="清除" cancelText="取消" onConfirm={clearKey}><Button danger loading={saving}>清除密钥</Button></Popconfirm>}
          </div>
        </Form>
      </section>

      <section className="glass-panel usage-card" hidden={section !== 'overview'}>
        {usageError && <Alert type="error" showIcon message="用量读取失败" description={usageError} />}
        <div className="panel-heading"><div><Text className="panel-kicker">USAGE OBSERVATORY</Text><Title level={4}>用量分析</Title><Text type="secondary">统计来源：本地账本已记录的 Provider 回执；不代表供应商账户完整账单。</Text></div><DatabaseOutlined className="heading-icon" /></div>
        {usage?.usage_by_source && <Table size="small" pagination={false} scroll={{ x: 760 }} rowKey="source" dataSource={usage.usage_by_source} columns={[
          { title: '用量来源', dataIndex: 'source', render: value => ({ platform_agent: '主任务 Agent', secmind: 'SecMind 分析引擎', security_runtime_worker: 'Security Runtime Worker' }[value] || value) },
          { title: '已知 Token', render: (_, row) => row.token_usage_available ? row.total_tokens.toLocaleString() : '—' },
          { title: '调用 / 执行次数', render: (_, row) => `${row.call_count} ${row.call_unit === 'cli_execution' ? '次 CLI 执行' : '次请求'}` },
          { title: '部分确认', render: (_, row) => row.partial_usage_count || 0 },
          { title: '无直接用量回执', dataIndex: 'missing_usage_count' },
          { title: '同步状态', dataIndex: 'status', render: value => ({ synced: '已同步', awaiting_receipts: '等待首次回执', unavailable: '来源不可用', error: '同步失败', catching_up: '正在补齐历史' }[value] || value) },
        ]} />}
        {usage?.usage_by_source && <Text type="secondary">Worker 次数按 CLI 执行计，一次执行可能包含多轮模型响应。历史 Pi 与 Claude Code 会话已补录 {usage.backfilled_response_count || 0} 条响应，Token 已计入总量；空 CLI 回执可能已由会话补录覆盖，不能直接当作漏计次数。</Text>}
        {usage?.partial_usage_count > 0 && <Alert type="info" title={`有 ${usage.partial_usage_count} 次请求仅部分 Token 得到供应商确认；这里只计入已确认数字，未知部分仍保留为未知。`} />}
        {usage?.usage_by_source?.some(row => ['error', 'unavailable'].includes(row.status)) && <Alert type="warning" title="部分用量来源暂不可用，总计仅包含已同步记录。" />}
        {usage && <ModelSeriesChart usage={usage} />}
        {usage?.missing_usage_count > 0 && <Alert type="warning" title={`有 ${usage.missing_usage_count} 次请求或 CLI 执行没有直接用量回执；部分 Pi 与 Claude Code 用量已从会话补录，总量仍以可核验记录为准。`} />}
        {usage && <details className="model-budget-details"><summary>预算提醒设置 <span>仅提醒，不会自动停止调用</span></summary><UsageBudgetPanel usage={usage} usagePeriod={usagePeriod} setUsagePeriod={setUsagePeriod} quotaDraft={quotaDraft} setQuotaDraft={value => { quotaDirty.current = true; setQuotaDraft(value) }} quotaSaving={quotaSaving} saveQuota={saveQuota} /></details>}

      </section>
    </div>

  </div>
}

const periodMeta = {
  hourly: { label: '每小时', range: '最近 24 小时' },
  daily: { label: '每日', range: '最近 7 天' },
  monthly: { label: '每月', range: '最近 12 个月' },
}

function formatTokens(value) {
  const amount = Number(value || 0)
  if (amount >= 1_000_000) return `${(amount / 1_000_000).toFixed(1)}M`
  if (amount >= 1_000) return `${(amount / 1_000).toFixed(1)}K`
  return String(amount)
}

function UsageBudgetPanel({ usage, usagePeriod, setUsagePeriod, quotaDraft, setQuotaDraft, quotaSaving, saveQuota }) {
  const allPoints = usage?.series?.[usagePeriod] || []
  // Keep the API's longer history for reporting, but show only the latest
  // seven daily buckets here so adjacent columns remain readable.
  const points = usagePeriod === 'daily' ? allPoints.slice(-7) : allPoints
  const current = points.at(-1) || { tokens: 0, calls: 0, bucket: '' }
  const quota = Number(usage?.quota?.[usagePeriod] || 0)
  const known = current.calls === 0 || current.usage_receipt_count > 0
  const percent = quota ? Math.min(100, Math.round(Number(current.tokens || 0) / quota * 100)) : 0
  return <section className="usage-budget-panel">
    <header className="usage-budget-head">
      <div><BarChartOutlined /><span><b>预算提醒与消耗趋势</b><small>{periodMeta[usagePeriod].range} · Asia/Shanghai · Token</small></span></div>
      <Segmented size="small" value={usagePeriod} onChange={setUsagePeriod} options={Object.entries(periodMeta).map(([value, item]) => ({ value, label: item.label }))} />
    </header>
    <div className="usage-budget-summary">
      <div><small>当前周期已用</small><b>{known ? formatTokens(current.tokens) : '—'}</b><span>{current.calls || 0} 次调用 · {current.usage_receipt_count || 0} 份用量回执</span></div>
      <div><small>{periodMeta[usagePeriod].label}预算</small><b>{quota ? formatTokens(quota) : '未设置'}</b><span>{quota ? '仅提醒，不会停止调用' : '仅统计，不限制'}</span></div>
      <label><span>设置预算提醒</span><div><InputNumber min={0} precision={0} value={quotaDraft?.[usagePeriod] || 0} onChange={(value) => setQuotaDraft((currentDraft) => ({ ...(currentDraft || { hourly: 0, daily: 0, monthly: 0 }), [usagePeriod]: value || 0 }))} /><Button icon={<SaveOutlined />} loading={quotaSaving} onClick={saveQuota}>保存</Button></div></label>
    </div>
    {quota > 0 && known && <Progress percent={percent} showInfo status={percent >= 100 ? 'exception' : 'normal'} />}
    <div className="budget-trend">
      <div className="budget-trend-caption"><span>Token 消耗</span><span><i />实际用量{quota > 0 && <><em />当前预算 {formatTokens(quota)}</>}</span></div>
      <UsageChart key={usagePeriod} points={points} kind="budget" period={usagePeriod} label={`${periodMeta[usagePeriod].range}预算消耗趋势`} reference={quota} />
      <p className="budget-trend-footnote">{quota > 0 ? '虚线表示当前保存的预算，供各周期对照。' : '尚未设置预算，图表按实际用量自动缩放。'} 悬停或点选可查看明细。</p>
    </div>
  </section>
}
