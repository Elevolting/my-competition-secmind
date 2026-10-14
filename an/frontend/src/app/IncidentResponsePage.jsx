import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Empty, Input, Modal, Select, Space, Table, Tag, Typography, Upload } from 'antd'
import { UploadOutlined } from '@ant-design/icons'
import { getIncidentActions, getIncidentCommands, getIncidentLogs, getIncidentStatus,
  getIncidentEligibleUnblocks, getIncidentPendingApprovals,
  resolveIncidentApproval, startIncidentMonitor, stopIncidentMonitor, submitIncidentCommand,
  uploadIncidentSample, incidentEvidenceUrl } from '../api.js'
import { incidentFeedback } from './incidentFeedback.js'
const { Title, Text } = Typography
const labels = { partial: '部分完成', completed: '已执行', failed: '失败', interrupted: '中断待核对', awaiting_approval: '待审批', denied: '已拒绝', executing: '执行中' }
const historyPageSize = 20

export function IncidentResponsePage() {
  const { message } = App.useApp()
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [logPage, setLogPage] = useState(1)
  const [logTotal, setLogTotal] = useState(0)
  const [actions, setActions] = useState([])
  const [actionPage, setActionPage] = useState(1)
  const [actionTotal, setActionTotal] = useState(0)
  const [approvals, setApprovals] = useState([])
  const [approvalsAvailable, setApprovalsAvailable] = useState(false)
  const [eligibleUnblocks, setEligibleUnblocks] = useState([])
  const [groups, setGroups] = useState([])
  const [error, setError] = useState('')
  const [command, setCommand] = useState('collect_evidence')
  const [target, setTarget] = useState('local')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [detailActionId, setDetailActionId] = useState(null)
  const refreshSequence = useRef(0)
  const refreshInFlight = useRef(null)
  const operationInFlight = useRef(false)
  const refresh = useCallback((force = false) => {
    if (!force && refreshInFlight.current) return refreshInFlight.current
    const sequence = ++refreshSequence.current
    const request = (async () => {
      const [s, l, a, p, c, unblocks] = await Promise.allSettled([
        getIncidentStatus(), getIncidentLogs(historyPageSize, (logPage - 1) * historyPageSize),
        getIncidentActions(historyPageSize, (actionPage - 1) * historyPageSize),
        getIncidentPendingApprovals(), getIncidentCommands(), getIncidentEligibleUnblocks(),
      ])
      if (sequence !== refreshSequence.current) return null
      if (s.status === 'rejected') {
        setStatus(null); setLogs([]); setActions([]); setApprovals([]); setApprovalsAvailable(false); setGroups([]); setEligibleUnblocks([])
        setError(`状态：${s.reason.message}`)
        return false
      }
      setStatus(s.value)
      setLogs(l.status === 'fulfilled' ? l.value.logs : [])
      setLogTotal(l.status === 'fulfilled' ? l.value.total : 0)
      setActions(a.status === 'fulfilled' ? a.value.actions : [])
      setActionTotal(a.status === 'fulfilled' ? a.value.total : 0)
      setApprovals(p.status === 'fulfilled' ? p.value.approvals : [])
      setApprovalsAvailable(p.status === 'fulfilled')
      setGroups(c.status === 'fulfilled' ? c.value.groups : [])
      setEligibleUnblocks(unblocks.status === 'fulfilled' ? unblocks.value.actions : [])
      const failed = [[l, '审计日志'], [a, '执行回执'], [p, '审批队列'], [c, '命令目录'], [unblocks, '可撤销阻断记录']]
        .filter(([result]) => result.status === 'rejected')
        .map(([result, label]) => `${label}：${result.reason.message}`)
      setError(failed.join('；'))
      return failed.length === 0
    })()
    refreshInFlight.current = request
    void request.finally(() => {
      if (refreshInFlight.current === request) refreshInFlight.current = null
    })
    return request
  }, [actionPage, logPage])
  useEffect(() => { refresh(); const timer = setInterval(() => refresh(), 5000); return () => { clearInterval(timer); refreshSequence.current += 1; refreshInFlight.current = null } }, [refresh])
  const perform = async (fn, operation = 'command') => {
    if (operationInFlight.current) return
    operationInFlight.current = true
    setBusy(true)
    try {
      const result = await fn()
      const feedback = incidentFeedback(result, operation)
      message[feedback.level](feedback.text)
      if (await refresh(true) === false) message.warning('操作回执已返回，应急数据暂未刷新')
      return result
    } catch (e) {
      setError(e.message)
      message.error(e.message)
    } finally { operationInFlight.current = false; setBusy(false) }
  }
  const inventory = status?.inventory
  const detail = actions.find(action => action.action_id === detailActionId) || null
  const responseCommand = ['isolate_sample', 'restore_snapshot', 'block_indicator', 'unblock_indicator'].includes(command)
  return <div className="incident-page">
    <section className="page-intro"><div><Text className="panel-kicker">LOCAL HOST RESPONSE</Text><Title level={2}>本机监控与应急处置</Title><p>采集当前部署机器的进程与监听端口，保留证据；文件隔离、恢复和防火墙变更经审批后实际执行。</p></div>
      <Space><Tag color={status?.running ? 'green' : 'default'}>{status ? status.running ? '采集中' : '采集已停止' : '状态未知'}</Tag>
      <Button loading={busy} disabled={!status} onClick={() => perform(() => status.running ? stopIncidentMonitor() : startIncidentMonitor())}>{status?.running ? '停止采集' : '启动采集'}</Button><Button onClick={() => refresh(true)}>刷新</Button></Space></section>
    {error && <Alert type="error" showIcon message={`应急数据读取失败：${error}`} />}
    <section className="incident-metrics">{[['本机', inventory?.hostname], ['进程', inventory?.processes?.length], ['监听端口', inventory?.listeners?.length], ['待审批', status?.pending_approvals]].map(([label, value]) => <div className="incident-metric" key={label}><span><small>{label}</small><b>{value ?? '—'}</b></span></div>)}</section>
    <section className="glass-panel" style={{ padding: 20 }}>
      <Title level={4}>本机采集结果</Title>
      <p>{inventory ? `采集于 ${new Date(inventory.collected_at).toLocaleString()} · ${inventory.platform}` : '尚未采集；启动采集或执行一次取证快照。'}</p>
      {inventory?.errors?.length > 0 && <Alert type="warning" message="部分数据读取失败，以下结果不完整" description={JSON.stringify(inventory.errors)} />}
      <Alert type="info" message="监听端口反映本机服务暴露，不代表已遭受攻击；防火墙可能限制其可达性。" />
      <Table size="small" dataSource={inventory?.listeners || []} rowKey={row => `${row.address}:${row.port}:${row.pid}`} pagination={{ pageSize: 8 }} columns={[
        { title: '地址', dataIndex: 'address' }, { title: '端口', dataIndex: 'port' }, { title: 'PID', dataIndex: 'pid' },
        { title: '进程', dataIndex: 'process' }, { title: '监听范围', render: (_, row) => row.wildcard ? '所有接口' : '指定地址' },
      ]} />
      <details><summary>进程清单（{inventory?.processes?.length || 0}）</summary><Table size="small" rowKey="pid" dataSource={inventory?.processes || []} pagination={{ pageSize: 10 }} columns={[{ title: 'PID', dataIndex: 'pid' }, { title: '进程', dataIndex: 'name' }, { title: '程序路径', dataIndex: 'exe', ellipsis: true }]} /></details>
      {inventory?.security_events && <details open><summary>Windows 登录失败日志（近 24 小时，最多 200 条；不直接判定为攻击）</summary>
        {!inventory.security_events.complete && <Alert type="warning" message="安全日志读取失败，不能按 0 条解释" description={inventory.security_events.errors.join('；')} />}
        <Table size="small" rowKey="record_id" dataSource={inventory.security_events.records || []} pagination={{ pageSize: 5 }} columns={[{ title: '时间', dataIndex: 'time' }, { title: '来源 IP', dataIndex: 'source_ip' }, { title: '登录类型', dataIndex: 'logon_type' }, { title: 'Windows 状态码', dataIndex: 'status' }]} />
      </details>}
      <p>基线：{status?.baseline_at || '尚未设置'}；新增监听端口：{inventory?.new_listeners?.length ?? '—'}</p>
      {!!inventory?.new_listeners?.length && <pre>{JSON.stringify(inventory.new_listeners, null, 2)}</pre>}
    </section>
    <section className="glass-panel" style={{ padding: 20 }}>
      <Title level={4}>命令与证据</Title>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Select aria-label="处置命令" style={{ width: '100%' }} value={command} onChange={value => { setCommand(value); setTarget(['isolate_sample', 'restore_snapshot', 'block_indicator', 'unblock_indicator'].includes(value) ? '' : 'local') }} options={groups.map(group => ({ label: group.label, options: group.commands.map(c => ({ value: c.value, label: `${c.label}${c.risk_level ? '（需审批）' : ''}` })) }))} />
        {command === 'isolate_sample' && <><Upload showUploadList={false} beforeUpload={file => { perform(async () => { const result = await uploadIncidentSample(file); setTarget(result.path); return result }, 'upload'); return false }}><Button disabled={!status || busy} icon={<UploadOutlined />}>上传待隔离文件</Button></Upload><Text type="secondary">可操作目录：{status?.allowed_roots?.join('；')}。上传只保存文件，不执行内容。</Text></>}
        {command === 'restore_snapshot' ? <Select aria-label="隔离记录" placeholder="选择隔离记录" style={{ width: '100%' }} value={target || undefined} onChange={setTarget} options={(status?.quarantines || []).filter(q => q.status !== 'restored').map(q => ({ value: q.id, label: `${q.original_path} · ${q.id}` }))} />
        : command === 'unblock_indicator' ? <Select aria-label="阻断记录" placeholder="选择本平台创建的阻断动作" style={{ width: '100%' }} value={target || undefined} onChange={setTarget} options={eligibleUnblocks.map(a => ({ value: a.action_id, label: `${a.target} · ${a.action_id}` }))} />
        : <Input aria-label="操作目标" value={target} onChange={e => setTarget(e.target.value)} placeholder={command === 'block_indicator' ? '远端 IP，例如 192.0.2.1' : command === 'isolate_sample' ? '上传后自动填入路径' : 'local'} />}
        {command === 'block_indicator' && <Alert type="warning" message="审批后创建真实的 Windows 出站阻断规则；需要 API 进程具备管理员权限。可以通过撤销命令删除本平台规则。" />}
        <Input.TextArea aria-label="处置原因" value={reason} onChange={e => setReason(e.target.value)} placeholder="处置原因（可选）" rows={2} />
        <Button type="primary" loading={busy} disabled={!target || !status || (responseCommand && !approvalsAvailable)} onClick={() => perform(() => submitIncidentCommand({ command, target, reason }))}>{responseCommand ? '提交审批' : '执行采集命令'}</Button>
      </Space>
    </section>
    <section className="glass-panel" style={{ padding: 20 }}><Title level={4}>待审批动作</Title>
      {approvals.filter(a => a.status === 'pending').map(a => <div key={a.approval_id} style={{ padding: '12px 0' }}><b>{a.command}</b><p>{a.target}</p><p>{a.reason}</p><Space>
        <Button loading={busy} disabled={!status} type="primary" onClick={() => perform(() => resolveIncidentApproval(a.approval_id, { decision: 'approve' }))}>批准并执行</Button>
        <Button disabled={busy || !status} onClick={() => perform(() => resolveIncidentApproval(a.approval_id, { decision: 'deny' }))}>拒绝</Button></Space></div>)}
      {approvalsAvailable && !approvals.some(a => a.status === 'pending') && <Empty description="没有待审批动作" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
    </section>
    <section className="glass-panel" style={{ padding: 20 }}><Title level={4}>执行回执</Title><Table rowKey="action_id" dataSource={actions} pagination={{ current: actionPage, pageSize: historyPageSize, total: actionTotal, showTotal: total => `共 ${total} 条` }} onChange={pagination => { setDetailActionId(null); setActionPage(pagination.current) }} columns={[
      { title: '动作', dataIndex: 'label' }, { title: '目标', dataIndex: 'target', ellipsis: true },
      { title: '状态', render: (_, a) => <Tag color={a.status === 'completed' ? 'green' : a.status === 'failed' ? 'red' : 'default'}>{labels[a.status] || a.status}</Tag> },
      { title: '结果', render: (_, a) => <Space><Button size="small" onClick={() => setDetailActionId(a.action_id)}>查看回执</Button>{a.result?.evidence_id && <a href={incidentEvidenceUrl(a.result.evidence_id)} download>下载证据</a>}</Space> },
    ]} /></section>
    <section className="glass-panel" style={{ padding: 20 }}><Title level={4}>审计日志</Title><Table size="small" rowKey="sequence" dataSource={logs} pagination={{ current: logPage, pageSize: historyPageSize, total: logTotal, showTotal: total => `共 ${total} 条` }} onChange={pagination => setLogPage(pagination.current)} columns={[{ title: '时间', dataIndex: 'timestamp', render: t => new Date(t).toLocaleString() }, { title: '事件', dataIndex: 'event_type' }, { title: '详情', dataIndex: 'message' }]} /></section>
    <Modal open={!!detail} title="执行回执" onCancel={() => setDetailActionId(null)} footer={null} width={850}><pre style={{ whiteSpace: 'pre-wrap', maxHeight: '65vh', overflow: 'auto' }}>{JSON.stringify(detail, null, 2)}</pre></Modal>
  </div>
}
