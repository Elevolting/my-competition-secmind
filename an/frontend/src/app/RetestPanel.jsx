import React, { useEffect, useMemo, useRef, useState } from 'react'
import { LinkOutlined, ReloadOutlined, UploadOutlined } from '@ant-design/icons'
import { Alert, App, Button, Input, InputNumber, Modal, Select, Space, Tag, Typography, Upload } from 'antd'
import { useNavigate } from 'react-router-dom'
import {
  cancelRetest, createRetest, getReport, getRetest, listRetests, recordRetestResult, uploadFile,
} from '../api.js'
import './retest-panel.css'

const { Text } = Typography
const terminal = new Set(['completed', 'failed', 'stopped'])
const labels = {
  pending: '待执行', dispatching: '提交中', running: '复核中', awaiting_result: '待登记结论', completed: '已登记',
  failed: '失败', stopped: '已取消', reproduced: '仍可复现', fixed: '已修复',
  supported: '支持原结论', refuted: '推翻原结论', inconclusive: '无法确认',
}
const roles = {
  penetration: { reproduced: ['proof'], fixed: ['trigger', 'baseline', 'conditions'] },
  code_audit: { reproduced: ['validation'], fixed: ['path_coverage', 'validation'] },
  reverse: { supported: ['verification'], refuted: ['verification'] },
  log_analysis: { supported: ['verification', 'material_scope'], refuted: ['verification', 'material_scope'] },
  incident_response: { supported: ['verification', 'material_scope'], refuted: ['verification', 'material_scope'] },
}
const roleLabels = {
  proof: '漏洞证明', trigger: '原触发检查', baseline: '正常对照', conditions: '可比前置条件',
  validation: '验证结果', path_coverage: '原路径覆盖', verification: '重新取证', material_scope: '材料与时间范围',
}

export async function conclusionReference(section, index, value) {
  const raw = new TextEncoder().encode(String(value))
  const digest = await crypto.subtle.digest('SHA-256', raw)
  return `${section}:${index}:${Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')}`
}

export function RetestPanel({ runId, kind, reference, conclusion, moduleRoute, originalEvidence = [] }) {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [history, setHistory] = useState([])
  const [selected, setSelected] = useState(null)
  const [childEvidence, setChildEvidence] = useState([])
  const [notes, setNotes] = useState('')
  const [files, setFiles] = useState([])
  const [budget, setBudget] = useState({})
  const [verdict, setVerdict] = useState('inconclusive')
  const [summary, setSummary] = useState('')
  const [checks, setChecks] = useState({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const createAttempt = useRef(null)
  const module = moduleRoute === 'audit' ? 'code_audit' : moduleRoute
  const verdicts = Object.keys(roles[module] || {})
  const required = roles[module]?.[verdict] || []
  const active = history.find(item => !terminal.has(item.status))
  const evidenceOptions = useMemo(() => childEvidence.map(item => ({
    value: item.evidence_id, label: `${item.evidence_id.slice(0, 12)} · ${item.summary.slice(0, 110)}`,
  })), [childEvidence])

  async function reload(next = selected) {
    const listed = await listRetests(runId)
    const items = (listed.retests || []).filter(item => item.source_kind === kind && item.source_ref === reference)
    setHistory(items)
    const chosen = next?.retest_id || items[0]?.retest_id
    if (!chosen) { setSelected(null); setChildEvidence([]); return }
    const detail = await getRetest(runId, chosen)
    setSelected(detail)
    if (detail.status === 'awaiting_result' || detail.status === 'completed') {
      try { setChildEvidence((await getReport(detail.child_run_id)).evidence || []) }
      catch { setChildEvidence([]) }
    } else setChildEvidence([])
  }

  useEffect(() => {
    if (!open) return undefined
    let alive = true
    const tick = () => reload().catch(err => { if (alive) setError(err.message) })
    tick()
    const timer = setInterval(tick, 4000)
    return () => { alive = false; clearInterval(timer) }
  }, [open, runId, kind, reference, selected?.retest_id])

  async function start() {
    if (busy) return
    setBusy(true); setError('')
    try {
      if (!createAttempt.current) {
        const attachments = []
        for (const file of files) attachments.push({ ref: (await uploadFile(file.originFileObj)).ref })
        createAttempt.current = {
          source_kind: kind, source_ref: reference, request_id: crypto.randomUUID(), notes, attachments,
          ...Object.fromEntries(Object.entries(budget).filter(([, value]) => value != null)),
        }
      }
      const created = await createRetest(runId, createAttempt.current)
      await reload(created)
      createAttempt.current = null
      message.success('独立复核已创建')
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  async function finish() {
    if (!selected || busy) return
    setBusy(true); setError('')
    try {
      const result = await recordRetestResult(runId, selected.retest_id, { verdict, summary, checks })
      await reload(result)
      message.success('复核结论已保存')
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  async function cancel() {
    if (!selected || busy) return
    setBusy(true); setError('')
    try { await cancelRetest(runId, selected.retest_id); await reload(); message.success('复核已取消') }
    catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return <span className="retest-entry">
    <Button size="small" icon={<ReloadOutlined />} onClick={() => setOpen(true)}>独立复核</Button>
    <Modal title="独立复核" open={open} width={760} footer={null} onCancel={() => setOpen(false)} destroyOnHidden>
      <div className="retest-panel">
        <div className="retest-source"><Text strong>{kind === 'finding' ? '原发现' : '原结论'}</Text>
          <span>{conclusion}</span><Text type="secondary">原证据：{originalEvidence.join('、') || '未关联'}</Text>
        </div>
        {error && <Alert type="error" showIcon title={error} />}
        <div className="retest-history"><Text strong>复核历史</Text>
          <Space wrap>{history.map(item => <Button key={item.retest_id} size="small"
            type={selected?.retest_id === item.retest_id ? 'primary' : 'default'} onClick={() => reload(item).catch(err => setError(err.message))}>
            {new Date(item.created_at).toLocaleString('zh-CN')} · {labels[item.verdict || item.status]}
          </Button>)}</Space>
        </div>
        {selected && <div className="retest-detail">
          <Space wrap><Tag>{labels[selected.status] || selected.status}</Tag>
            <Button size="small" icon={<LinkOutlined />} onClick={() => navigate(`/workbench?run=${encodeURIComponent(selected.child_run_id)}`)}>查看子任务</Button>
            {!terminal.has(selected.status) && <Button size="small" danger loading={busy}
              disabled={selected.status === 'dispatching'} onClick={cancel}>取消复核</Button>}
          </Space>
          {selected.error && <Alert type="warning" title={selected.error} />}
          {selected.summary && <p>{selected.summary}</p>}
          <Text type="secondary">原证据：{(selected.snapshot?.evidence || []).map(item => item.evidence_id).join('、') || '无'}</Text>
          <Text type="secondary">本次证据：{(selected.evidence_ids || []).join('、') || (childEvidence.map(item => item.evidence_id).join('、') || '尚无')}</Text>
          {selected.status === 'awaiting_result' && <div className="retest-result">
            <Select aria-label="复核结论" value={verdict} onChange={value => { setVerdict(value); setChecks({}) }}
              options={[...verdicts, 'inconclusive'].map(value => ({ value, label: labels[value] }))} />
            <Input.TextArea aria-label="结论依据" value={summary} onChange={event => setSummary(event.target.value)}
              maxLength={4000} rows={3} placeholder="写明实际检查、观察结果及无法确认时的阻塞原因" />
            {required.map(role => <label key={role}>{roleLabels[role]}
              <Select mode="multiple" aria-label={roleLabels[role]} value={checks[role] || []} options={evidenceOptions}
                onChange={value => setChecks(current => ({ ...current, [role]: value }))} />
            </label>)}
            <Button type="primary" loading={busy} disabled={!summary.trim() || required.some(role => !checks[role]?.length)}
              onClick={finish}>保存结论</Button>
          </div>}
        </div>}
        {!active && <div className="retest-create">
          <Text strong>发起新复核</Text>
          <Input.TextArea aria-label="复核补充说明" value={notes}
            onChange={event => { createAttempt.current = null; setNotes(event.target.value) }}
            maxLength={2000} rows={2} placeholder="补充修复版本或需要核对的条件" />
          <Upload multiple beforeUpload={() => false} fileList={files}
            onChange={({ fileList }) => { createAttempt.current = null; setFiles(fileList) }}>
            <Button icon={<UploadOutlined />}>添加本次材料</Button>
          </Upload>
          <Space wrap>{[['max_runtime_seconds', '时限（秒）', 60], ['max_tool_calls', '工具调用', 1],
            ['max_model_calls', '模型请求', 1]].map(([key, label, min]) => <label key={key}>{label}
              <InputNumber aria-label={label} min={min} max={key === 'max_runtime_seconds' ? 7200 : key === 'max_model_calls' ? 10000 : 100000}
                value={budget[key] ?? null} placeholder="默认"
                onChange={value => { createAttempt.current = null; setBudget(current => ({ ...current, [key]: value })) }} /></label>)}</Space>
          <Button type="primary" loading={busy} onClick={start}>发起复核</Button>
        </div>}
      </div>
    </Modal>
  </span>
}

export function RetestConclusion({ runId, section, index, text, moduleRoute, originalEvidence }) {
  const [reference, setReference] = useState('')
  useEffect(() => {
    let alive = true
    conclusionReference(section, index, text).then(value => { if (alive) setReference(value) })
    return () => { alive = false }
  }, [section, index, text])
  return reference ? <RetestPanel runId={runId} kind="conclusion" reference={reference}
    conclusion={text} moduleRoute={moduleRoute} originalEvidence={originalEvidence} /> : null
}
