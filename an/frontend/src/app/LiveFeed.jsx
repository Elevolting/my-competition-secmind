import React, { useMemo, useState } from 'react'
import { Empty, Input, Select, Switch, Tag, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { compactId, formatTime, projectEvent } from './runtimeModel.js'

const { Text } = Typography

export function LiveFeed({ events, selectedId, onSelect, design = false }) {
  const [query, setQuery] = useState(''); const [category, setCategory] = useState('all'); const [follow, setFollow] = useState(true)
  const rows = useMemo(() => events.map(projectEvent).filter((row) => {
    const matchCategory = category === 'all' || row.category === category
    return matchCategory && `${row.title} ${row.actor} ${row.summary} ${JSON.stringify(row.payload)}`.toLowerCase().includes(query.toLowerCase())
  }), [events, query, category])

  return <div className="live-feed">
    <div className="feed-controls">
      <Input prefix={<SearchOutlined />} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索事件、Agent、工具" />
      <Select value={category} onChange={setCategory} options={[{ value: 'all', label: '全部类别' }, { value: 'agent', label: 'Agent / AI' }, { value: 'runtime', label: '运行' }, { value: 'planning', label: '规划' }, { value: 'tool', label: '工具' }, { value: 'security', label: '安全' }, { value: 'verification', label: '验证' }, { value: 'report', label: '报告' }]} />
      <span className="follow-control"><Switch size="small" checked={follow} onChange={setFollow} /> 自动跟随</span><Text type="secondary">{rows.length}/{events.length}</Text>
    </div>
    <div className={`feed-scroll ${follow ? 'follow-latest' : ''}`}>
      {!rows.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无运行事件" /> : rows.map((row) => <button type="button" key={row.event_id} className={`feed-row is-${row.category} ${selectedId === row.event_id ? 'is-selected' : ''}`} onClick={() => onSelect?.(row)}><span className="feed-sequence">{String(row.sequence).padStart(2, '0')}</span><span className="feed-body"><b>{row.title}</b><small>{row.summary || `${row.actor} · ${formatTime(row.timestamp)}`}</small><span><Tag bordered={false}>{row.category}</Tag>{row.actor} · {compactId(row.event_id)}</span></span>{design && <Tag color="cyan">演示</Tag>}</button>)}
    </div>
  </div>
}
