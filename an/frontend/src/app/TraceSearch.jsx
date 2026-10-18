import React, { useEffect, useRef, useState } from 'react'
import { Alert, Button, Empty, Input, Modal, Space, Tag } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { searchRunTraces, getRunTrace } from '../api.js'

export default function TraceSearch({ runId, focus, graph }) {
  const [keyword, setKeyword] = useState('')
  const [worker, setWorker] = useState('')
  const [module, setModule] = useState('')
  const [items, setItems] = useState([])
  const [cursor, setCursor] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState(null)
  const serial = useRef(0)

  useEffect(() => {
    const ticket = ++serial.current
    setItems([]); setCursor(null); setError(''); setDetail(null); setBusy(true)
    searchRunTraces(runId).then(data => {
      if (ticket === serial.current) { setItems(data.items); setCursor(data.next_cursor) }
    }).catch(cause => {
      if (ticket === serial.current) setError(cause.message)
    }).finally(() => {
      if (ticket === serial.current) setBusy(false)
    })
    return () => { ++serial.current }
  }, [runId])

  async function search(next = false) {
    const ticket = ++serial.current
    setBusy(true); setError('')
    try {
      const data = await searchRunTraces(runId, {
        keyword, ...(worker ? { worker } : {}), ...(module ? { module } : {}),
        ...(next && cursor !== null ? { cursor } : {}),
      })
      if (ticket === serial.current) { setItems(old => next ? [...old, ...data.items] : data.items); setCursor(data.next_cursor) }
    } catch (cause) { if (ticket === serial.current) setError(cause.message) }
    finally { if (ticket === serial.current) setBusy(false) }
  }

  async function open(item) {
    const ticket = serial.current
    try {
      const data = await getRunTrace(runId, item.trace_id)
      if (ticket === serial.current) setDetail(data)
    } catch (cause) { if (ticket === serial.current) setError(cause.message) }
  }

  return <div className="execution-detail-scroll execution-trace-search">
    <Input.Search aria-label="搜索执行记录" placeholder="搜索执行记录" value={keyword}
      onChange={event => setKeyword(event.target.value)} onSearch={() => search()} loading={busy} enterButton={<SearchOutlined />} />
    <Space wrap className="execution-trace-filters">
      <Input aria-label="按 Worker 筛选" placeholder="Worker" value={worker} onChange={event => setWorker(event.target.value)} />
      <Input aria-label="按模块筛选" placeholder="模块" value={module} onChange={event => setModule(event.target.value)} />
      <Button onClick={() => search()} loading={busy}>筛选</Button>
    </Space>
    {error && <Alert type="error" message={error} showIcon />}
    {!items.length && !busy && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无执行记录" />}
    {items.map(item => {
      const linked = graph.nodes?.find(node => node.raw_id === (item.intent_id || item.step_id))
      return <div key={item.trace_id} className="execution-trace-row">
        <div><strong>{item.tool || item.event_type}</strong><Tag>{({ complete: '完整', truncated: '截断', unavailable: '不可用' })[item.output_state]}</Tag></div>
        <small>{item.worker} · {item.module} · {new Date(item.timestamp).toLocaleString('zh-CN')}</small>
        <p>{item.match_excerpt || item.summary}</p>
        <Space><Button size="small" onClick={() => open(item)}>详情</Button>
          {linked && <Button size="small" onClick={() => focus(linked.id)}>跳转步骤</Button>}</Space>
      </div>
    })}
    {cursor !== null && <Button block onClick={() => search(true)} loading={busy}>更多记录</Button>}
    <Modal title="执行记录详情" open={!!detail} onCancel={() => setDetail(null)} footer={null} width={800}>
      <pre className="execution-evidence-output">{detail ? JSON.stringify(detail, null, 2) : ''}</pre>
    </Modal>
  </div>
}
