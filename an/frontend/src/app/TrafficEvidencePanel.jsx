import React, { useState } from 'react'
import { DownloadOutlined, LinkOutlined, PaperClipOutlined, UploadOutlined } from '@ant-design/icons'
import { Alert, App, AutoComplete, Button, Input, InputNumber, Modal, Segmented, Select, Space, Tag, Typography, Upload } from 'antd'
import { bindTrafficEvidence, createTrafficEvidence, getTrafficEvidence, trafficEvidenceExportUrl, uploadFile } from '../api.js'

const roles = [
  { value: 'baseline', label: '正常对照' },
  { value: 'proof', label: '漏洞证明' },
  { value: 'verification', label: '复测证据' },
  { value: 'supporting', label: '辅助材料' },
]
const roleLabel = Object.fromEntries(roles.map(({ value, label }) => [value, label]))

function Exchange({ title, value }) {
  return <section className="traffic-exchange"><Typography.Text strong>{title}</Typography.Text>
    <pre>{(value?.headers || []).map(header => `${header.name}: ${header.value}`).join('\n') || '无请求头'}</pre>
    <pre>{value?.body ?? '正文未记录'}</pre>
  </section>
}

export function TrafficEvidencePanel({ runId, finding, events, evidence = [], onChanged }) {
  const { message } = App.useApp()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState('har')
  const [sourceRef, setSourceRef] = useState('')
  const [file, setFile] = useState(null)
  const [entryIndex, setEntryIndex] = useState(0)
  const [role, setRole] = useState('proof')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState(null)
  const bindings = finding.raw?.traffic_bindings || []
  const options = events.filter(event =>
    (event.event_type === 'tool.completed' || event.event_type === 'mcp.call.completed') &&
    (kind !== 'ledger' || event.payload?.result || event.payload?.data))
    .slice(-30).reverse().map(event => ({
      value: kind === 'ledger' ? event.event_id : event.payload?.call_id || event.payload?.receipt_id,
      label: `${event.payload?.tool || event.event_type} · ${event.event_id?.slice(0, 8)}`,
    })).filter(option => option.value)

  async function view(evidenceId) {
    setOpen(true)
    setDetail(null)
    setBusy(true)
    try { setDetail(await getTrafficEvidence(runId, evidenceId)) }
    catch (error) { message.error(`读取流量证据失败：${error.message}`) }
    finally { setBusy(false) }
  }

  async function create() {
    if (busy || (kind === 'har' ? !file : !sourceRef.trim())) return
    setBusy(true)
    try {
      const reference = kind === 'har' ? (await uploadFile(file)).ref : sourceRef.trim()
      const created = await createTrafficEvidence(runId, {
        source_kind: kind, source_ref: reference, entry_index: entryIndex ?? 0,
      })
      setDetail({ ...created, bindings: [] })
      message.success('流量快照已保存')
      try { await onChanged() } catch { message.warning('快照已保存，任务视图暂未刷新') }
    } catch (error) { message.error(`保存流量证据失败：${error.message}`) }
    finally { setBusy(false) }
  }

  async function bind() {
    if (!detail || busy) return
    setBusy(true)
    try {
      await bindTrafficEvidence(runId, finding.finding_id, {
        evidence_id: detail.evidence_id, role, note,
      })
      setDetail(await getTrafficEvidence(runId, detail.evidence_id))
      message.success('已关联到发现')
      try { await onChanged() } catch { message.warning('证据已关联，任务视图暂未刷新') }
    } catch (error) { message.error(`关联流量证据失败：${error.message}`) }
    finally { setBusy(false) }
  }

  const snapshot = detail?.snapshot
  const missing = snapshot?.missing || {}
  return <div className="traffic-evidence-panel">
    <Space wrap>
      {bindings.map(binding => <Button size="small" key={`${binding.evidence_id}:${binding.role}`}
        icon={<PaperClipOutlined />} onClick={() => view(binding.evidence_id)}>
        {roleLabel[binding.role] || binding.role} · {binding.evidence_id.slice(0, 8)}
      </Button>)}
      <Button size="small" icon={<LinkOutlined />} onClick={() => { setDetail(null); setOpen(true) }}>关联流量证据</Button>
    </Space>
    <Modal title="流量证据" open={open} width={760} footer={null} onCancel={() => setOpen(false)} destroyOnHidden>
      <div className="traffic-evidence-modal">
        {evidence.some(item => item.metadata?.kind === 'traffic') && <Select
          aria-label="选择已有流量快照" placeholder="选择当前任务已保存的流量快照"
          value={detail?.evidence_id} onChange={view} options={evidence.filter(item => item.metadata?.kind === 'traffic')
            .map(item => ({ value: item.evidence_id, label: item.summary }))} />}
        <Segmented value={kind} onChange={value => { setKind(value); setSourceRef(''); setFile(null) }} options={[
          { value: 'har', label: 'HAR 文件' }, { value: 'mcp', label: 'MCP 回执' }, { value: 'ledger', label: '账本记录' },
        ]} />
        <div className="traffic-evidence-source">
          {kind === 'har' ? <Upload accept=".har,application/json" maxCount={1} beforeUpload={() => false}
            fileList={file ? [{ uid: file.uid, name: file.name, status: 'done' }] : []}
            onChange={({ fileList }) => setFile(fileList.at(-1)?.originFileObj || null)}>
            <Button icon={<UploadOutlined />}>选择 HAR</Button>
          </Upload> : <AutoComplete value={sourceRef} onChange={setSourceRef} options={options}
            placeholder={kind === 'mcp' ? 'MCP 调用编号' : '账本事件编号'} style={{ flex: 1, minWidth: 200 }} />}
          <label>条目序号 <InputNumber aria-label="条目序号" value={entryIndex} onChange={setEntryIndex}
            min={0} max={10000} precision={0} style={{ width: 80 }} /></label>
          <Button type="primary" loading={busy} disabled={kind === 'har' ? !file : !sourceRef.trim()}
            onClick={create}>保存快照</Button>
        </div>
        {snapshot && <>
          <div className="traffic-evidence-summary">
            <strong>{snapshot.method} {snapshot.url}</strong>
            <Tag>{snapshot.status_code}</Tag>
            {snapshot.truncated && <Tag color="warning">内容截断</Tag>}
            {(missing.request_body || missing.response_body) && <Tag color="warning">正文缺失</Tag>}
            {!snapshot.truncated && !missing.request_body && !missing.response_body && <Tag color="success">记录完整</Tag>}
          </div>
          <Typography.Text type="secondary">来源：{snapshot.source.kind} · {snapshot.source.reference} · SHA-256 {detail.sha256}</Typography.Text>
          {(snapshot.truncated || missing.request_body || missing.response_body) && <Alert type="warning" showIcon
            title="证据内容不完整" description="缺失或截断部分无法用于判断原始 HTTP 交换的完整内容。" />}
          <div className="traffic-evidence-exchanges">
            <Exchange title="请求" value={snapshot.request} />
            <Exchange title="响应" value={snapshot.response} />
          </div>
          <Space wrap>
            <Select value={role} onChange={setRole} options={roles} style={{ width: 130 }} />
            <Input value={note} onChange={event => setNote(event.target.value)} maxLength={1000}
              placeholder="用途备注（可选）" style={{ width: 220 }} />
            <Button type="primary" loading={busy} onClick={bind}>关联到当前发现</Button>
            <Button icon={<DownloadOutlined />} href={trafficEvidenceExportUrl(runId, detail.evidence_id)}>导出脱敏快照</Button>
          </Space>
        </>}
      </div>
    </Modal>
  </div>
}
