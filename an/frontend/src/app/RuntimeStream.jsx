import React, { useMemo } from 'react'
import { ApiOutlined, BulbOutlined, CodeOutlined, LoadingOutlined, RobotOutlined } from '@ant-design/icons'
import { Empty, Tag, Typography } from 'antd'
import { formatTime, projectStreams } from './runtimeModel.js'

const { Text } = Typography

export function RuntimeStream({ events, connected = false, active = false, replay = false, replaying = false }) {
  const items = useMemo(() => projectStreams(events), [events])
  const status = replay ? (replaying ? 'REPLAYING' : 'REPLAY') : !active ? '等待任务' : connected ? 'LIVE' : 'RECONNECTING'
  return <div className="runtime-stream">
    <div className="stream-disclosure"><RobotOutlined /><span><b>{replay ? 'AI 实时流回放' : 'AI 实时观察窗'}</b><small>展示可审计思考摘要、编排指令与模型公开输出；不展示隐藏推理。</small></span><Tag color={connected || replaying ? 'cyan' : 'default'}>{status}</Tag></div>
    <div className="stream-scroll">{items.length ? items.map((item) => <article className={`stream-card is-${item.kind}`} key={item.event_id || item.traceId}>
      <i>{item.kind === 'instruction' ? <ApiOutlined /> : item.kind === 'thought' ? <BulbOutlined /> : item.status === 'streaming' ? <LoadingOutlined spin /> : <CodeOutlined />}</i>
      <div><header><b>{item.kind === 'instruction' ? '编排指令' : item.kind === 'thought' ? `${item.agent} · 思考摘要` : `${item.stage || 'model'} · ${item.model || '模型'}`}</b><Text type="secondary">{item.timestamp ? formatTime(item.timestamp) : item.status}</Text></header><pre>{item.content || '模型正在建立响应流…'}{item.status === 'streaming' && <span className="stream-cursor" />}</pre>{item.usage && <footer>Input {item.usage.prompt_tokens || 0} · Output {item.usage.completion_tokens || 0} · Total {item.usage.total_tokens || ((item.usage.prompt_tokens || 0) + (item.usage.completion_tokens || 0))} · Cache {item.usage.cache_read_tokens || 0}</footer>}</div>
    </article>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="新任务启动后将在此实时显示 AI 摘要与指令" />}</div>
  </div>
}
