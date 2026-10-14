import React, { useEffect, useState } from 'react'
import { Alert, Button, Descriptions, Empty, Input, Modal, Select, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { getSkillUsage, getSkillUsageEvent } from '../api.js'
import './skill-usage.css'

const labels = { 'skill.loaded': '加载成功', 'skill.load_failed': '加载失败', 'tool.invoked': '实际调用', 'tool.completed': '调用返回', 'tool.failed': '调用异常' }
const purposes = { context: '上下文加载', plan_validation: '规划核验', work_contract: '执行前核验', primary_work_contract: '主模型核验' }
const pageSize = 20
const time = value => value ? new Date(value).toLocaleString('zh-CN') : '—'

export function SkillUsagePage() {
  const [filters, setFilters] = useState({ skill_id: '', run_id: '', role: '', event_type: '' })
  const [page, setPage] = useState(1)
  const [revision, setRevision] = useState(0)
  const [listing, setListing] = useState({ busy: true, data: null, error: '' })
  const [eventId, setEventId] = useState(null)
  const [detail, setDetail] = useState({ busy: false, data: null, error: '' })
  const filter = (key, value) => { setFilters(current => ({ ...current, [key]: value || '' })); setPage(1) }
  useEffect(() => {
    const controller = new AbortController()
    setListing({ busy: true, data: null, error: '' })
    getSkillUsage({ ...filters, offset: (page - 1) * pageSize, limit: pageSize }, controller.signal)
      .then(data => {
        if (controller.signal.aborted) return
        if (page > 1 && data.total_events <= (page - 1) * pageSize) { setPage(1); return }
        setListing({ busy: false, data, error: '' })
      })
      .catch(error => { if (!controller.signal.aborted) setListing({ busy: false, data: null, error: error.message }) })
    return () => controller.abort()
  }, [filters, page, revision])
  useEffect(() => {
    const controller = new AbortController()
    setDetail({ busy: !!eventId, data: null, error: '' })
    if (eventId) getSkillUsageEvent(eventId, controller.signal)
      .then(data => { if (!controller.signal.aborted) setDetail({ busy: false, data, error: '' }) })
      .catch(error => { if (!controller.signal.aborted) setDetail({ busy: false, data: null, error: error.message }) })
    return () => controller.abort()
  }, [eventId, revision])
  const data = listing.data
  const event = detail.data
  const usage = event?.payload?.skill_usage || event?.payload || {}
  return <div className="skill-usage">
    <div className="skill-usage-heading"><div><Typography.Title level={3}>技能使用统计</Typography.Title>
      <Typography.Paragraph>查看技能加载和实际工具调用，追溯任务、角色及原始事件。</Typography.Paragraph></div>
      <Button onClick={() => setRevision(value => value + 1)} loading={listing.busy}>刷新</Button></div>
    <Alert type="info" showIcon title="加载与调用分别统计" description="加载包括上下文读取和执行前核验。同一次调用可关联多个候选技能，调用总数只计一次；这些数据不代表漏洞检出率。事件类型筛选仅影响下方事件列表。旧任务没有执行事件时不补推统计。" />
    <div className="skill-usage-filters">
      <Input.Search aria-label="按技能筛选" placeholder="技能编号；unknown 表示未知" allowClear onSearch={value => filter('skill_id', value.trim())} />
      <Input.Search aria-label="按任务筛选技能" placeholder="工作台任务编号" allowClear onSearch={value => filter('run_id', value.trim())} />
      <Input.Search aria-label="按角色筛选" placeholder="角色编号；unknown 表示未知" allowClear onSearch={value => filter('role', value.trim())} />
      <Select aria-label="技能事件类型" placeholder="全部事件" allowClear value={filters.event_type || undefined}
        options={Object.entries(labels).map(([value, label]) => ({ value, label }))} onChange={value => filter('event_type', value)} />
    </div>
    {listing.error && <Alert type="error" showIcon title="技能统计加载失败" description={listing.error} action={<Button onClick={() => setRevision(value => value + 1)}>重试</Button>} />}
    {data?.unavailable_reason && <Alert type="warning" title={data.unavailable_reason} />}
    <div className="skill-usage-totals">
      <Statistic title="加载成功" value={data?.totals?.loads ?? '—'} /><Statistic title="加载失败" value={data?.totals?.load_failures ?? '—'} /><Statistic title="实际调用（去重）" value={data?.totals?.calls ?? '—'} />
    </div>
    <Table rowKey="skill_id" loading={listing.busy} dataSource={data?.skills || []} pagination={false} scroll={{ x: 800 }}
      locale={{ emptyText: <Empty description="没有可统计的技能事件" /> }} columns={[
        { title: '技能 / 候选归属', dataIndex: 'skill_id', render: value => value === 'unknown' ? '未知归属' : value },
        { title: '加载成功', dataIndex: 'loads' }, { title: '加载失败', dataIndex: 'load_failures' },
        { title: '关联调用', dataIndex: 'calls' }, { title: '调用成功', dataIndex: 'succeeded' },
        { title: '调用失败', dataIndex: 'failed' }, { title: '尚无结果', dataIndex: 'pending' },
      ]} />
    <Typography.Title level={4}>原始事件</Typography.Title>
    <Table rowKey="event_id" loading={listing.busy} dataSource={data?.events || []} scroll={{ x: 1050 }}
      pagination={{ current: page, pageSize, total: data?.total_events || 0, showSizeChanger: false, onChange: setPage }} columns={[
        { title: '时间', dataIndex: 'timestamp', render: time }, { title: '事件', dataIndex: 'event_type', render: value => <Tag>{labels[value] || value}</Tag> },
        { title: '技能', dataIndex: 'skill_ids', render: values => values?.join('、') || '未知归属' }, { title: '角色', dataIndex: 'role' },
        { title: '任务', dataIndex: 'run_id', render: (value, row) => row.workbench_run_ids?.length ? <Space wrap>{row.workbench_run_ids.map(id => <Link key={id} to={`/workbench?run=${encodeURIComponent(id)}`}>{id}</Link>)}</Space> : <span>分析引擎 {value}</span> },
        { title: '详情', render: (_, row) => <Button onClick={() => setEventId(row.event_id)}>查看事件</Button> },
      ]} />
    <Modal open={!!eventId} title="技能事件与来源" footer={null} width={850} onCancel={() => setEventId(null)}>
      {detail.busy && <div role="status"><Spin /> 正在加载事件…</div>}
      {detail.error && <Alert type="error" title="事件加载失败" description={detail.error} action={<Button onClick={() => setRevision(value => value + 1)}>重试</Button>} />}
      {event && <div className="skill-usage-detail"><Descriptions column={1} items={[
        { key: 'id', label: '事件编号', children: event.event_id }, { key: 'sequence', label: '任务事件序号', children: event.sequence },
        { key: 'time', label: '时间', children: time(event.timestamp) }, { key: 'type', label: '事件类型', children: labels[event.event_type] || event.event_type },
        { key: 'step', label: '步骤', children: usage.step_id || '未指定' },
        { key: 'attempt', label: '调用 / 加载 attempt', children: usage.invocation_attempt ?? usage.attempt ?? '未知' },
        { key: 'purpose', label: '加载用途 / 归因依据', children: purposes[usage.purpose] || (usage.attribution === 'verified_work_contract' ? '已核验执行契约中的候选技能' : '未知归属') },
      ]} /><Space wrap>{event.workbench_run_ids?.map(id => <Link key={id} to={`/audit/${encodeURIComponent(id)}`}>打开任务审计 {id}</Link>)}</Space>
        <pre>{JSON.stringify(event, null, 2)}</pre></div>}
    </Modal>
  </div>
}
