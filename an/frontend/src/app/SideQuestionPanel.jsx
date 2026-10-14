import React, { useCallback, useEffect, useRef, useState } from 'react'
import { ClearOutlined, LoadingOutlined, MessageOutlined, SendOutlined, StopOutlined } from '@ant-design/icons'
import { Button, Card, Empty, Input, List, Space, Tag, Typography } from 'antd'
import {
  cancelSideQuestion,
  clearSideQuestion,
  createSideQuestion,
  listSideQuestions,
} from '../api.js'
import './side-question-panel.css'

const { Text, Paragraph } = Typography
const ACTIVE_STATUSES = new Set(['queued', 'running'])
const STATUS_LABELS = {
  queued: ['排队中', 'processing'],
  running: ['回答中', 'processing'],
  completed: ['已完成', 'success'],
  failed: ['失败', 'error'],
  cancelled: ['已取消', 'default'],
  interrupted: ['已中断', 'warning'],
}

function statusTag(status) {
  const [label, color] = STATUS_LABELS[status] || [status || '未知', 'default']
  return <Tag color={color}>{label}</Tag>
}

function snapshotTime(item) {
  return item?.snapshot?.captured_at
    ? new Date(item.snapshot.captured_at).toLocaleString('zh-CN')
    : '快照时间未知'
}

export function SideQuestionPanel({ runId }) {
  const [items, setItems] = useState([])
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [busyId, setBusyId] = useState('')
  const [error, setError] = useState('')
  const runRef = useRef(runId)

  const refresh = useCallback(async () => {
    if (!runId) return
    const data = await listSideQuestions(runId)
    if (runRef.current === runId) setItems(data.items || [])
  }, [runId])

  useEffect(() => {
    runRef.current = runId
    setItems([])
    setQuestion('')
    setError('')
    if (!runId) return undefined
    let alive = true
    const load = async () => {
      try {
        const data = await listSideQuestions(runId)
        if (alive && runRef.current === runId) setItems(data.items || [])
      } catch (requestError) {
        if (alive && runRef.current === runId) setError(requestError.message)
      }
    }
    load()
    const timer = setInterval(() => {
      if (alive) load()
    }, 1800)
    return () => { alive = false; clearInterval(timer) }
  }, [runId])

  const submit = async () => {
    const value = question.trim()
    if (!value || submitting || !runId) return
    setSubmitting(true)
    setError('')
    try {
      await createSideQuestion(runId, { question: value })
      setQuestion('')
      await refresh()
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setSubmitting(false)
    }
  }

  const action = async (item, operation) => {
    setBusyId(item.question_id)
    setError('')
    try {
      const result = operation === 'cancel'
        ? await cancelSideQuestion(runId, item.question_id)
        : await clearSideQuestion(runId, item.question_id)
      setItems(current => current.map(entry => entry.question_id === item.question_id ? result.question : entry))
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusyId('')
    }
  }

  return <Card className="side-question-panel" size="small" title={<span><MessageOutlined /> 旁路问答</span>}>
    <Text type="secondary">基于当前任务已冻结的模型快照独立回答，不会改变主任务状态。</Text>
    <Space.Compact className="side-question-input">
      <Input.TextArea
        value={question}
        onChange={event => setQuestion(event.target.value)}
        onPressEnter={event => { if (!event.shiftKey) { event.preventDefault(); submit() } }}
        placeholder="针对当前任务追问一件具体事情"
        autoSize={{ minRows: 2, maxRows: 5 }}
        disabled={submitting}
        aria-label="旁路问题"
      />
      <Button type="primary" icon={<SendOutlined />} loading={submitting} disabled={!question.trim()} onClick={submit}>提问</Button>
    </Space.Compact>
    {error && <Text type="danger" role="alert">{error}</Text>}
    {!loading && !items.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="还没有旁路问题" />}
    <List
      className="side-question-list"
      dataSource={items}
      renderItem={item => <List.Item key={item.question_id}>
        <article className="side-question-item">
          <div className="side-question-meta"><Text strong>{item.question}</Text><span>{statusTag(item.status)}</span></div>
          <Text type="secondary">快照：{snapshotTime(item)}</Text>
          {item.answer && <Paragraph className="side-question-answer" ellipsis={{ rows: 5, expandable: true }}>{item.answer}</Paragraph>}
          {item.error_type && <Text type="danger">失败原因：{item.error_type}</Text>}
          <div className="side-question-actions">
            {ACTIVE_STATUSES.has(item.status) && <Button size="small" icon={<StopOutlined />} loading={busyId === item.question_id} onClick={() => action(item, 'cancel')}>取消</Button>}
            {item.answer && <Button size="small" icon={<ClearOutlined />} loading={busyId === item.question_id} onClick={() => action(item, 'clear')}>清除回答</Button>}
            {item.status === 'running' && <LoadingOutlined spin />}
          </div>
        </article>
      </List.Item>}
    />
  </Card>
}

