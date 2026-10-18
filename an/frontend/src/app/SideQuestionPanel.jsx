import React, { useCallback, useEffect, useRef, useState } from 'react'
import { ClearOutlined, LoadingOutlined, MessageOutlined, SendOutlined, StopOutlined } from '@ant-design/icons'
import { Button, Empty, Input, List, Tag, Typography } from 'antd'
import {
  cancelSideQuestion,
  clearSideQuestion,
  createSideQuestion,
  listSideQuestions,
} from '../api.js'
import './side-question-panel.css'

const { Text } = Typography
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

function AnswerStream({ item }) {
  const viewRef = useRef(null)
  const followRef = useRef(true)
  useEffect(() => {
    if (item.status === 'running' && followRef.current && viewRef.current) {
      viewRef.current.scrollTop = viewRef.current.scrollHeight
    }
  }, [item.answer, item.status])

  return <pre
    ref={viewRef}
    className={`side-question-answer${item.status === 'running' ? ' is-streaming' : ''}`}
    aria-live={item.status === 'running' ? 'polite' : undefined}
    onScroll={event => {
      const view = event.currentTarget
      followRef.current = view.scrollHeight - view.scrollTop - view.clientHeight < 48
    }}
  >{item.answer || '模型正在建立响应流…'}{item.status === 'running' && <span className="stream-cursor" />}</pre>
}

export function SideQuestionPanel({ runId }) {
  const [items, setItems] = useState([])
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [busyId, setBusyId] = useState('')
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState('')
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
    setLoadError('')
    setLoading(Boolean(runId))
    if (!runId) return undefined
    let alive = true
    let timer
    const load = async () => {
      let interval = 1800
      try {
        const data = await listSideQuestions(runId)
        if (alive && runRef.current === runId) {
          setItems(data.items || [])
          setLoadError('')
          if (data.items?.some(item => ACTIVE_STATUSES.has(item.status))) interval = 600
        }
      } catch (requestError) {
        if (alive && runRef.current === runId) setLoadError(requestError.message)
      } finally {
        if (alive && runRef.current === runId) setLoading(false)
        if (alive) timer = setTimeout(load, interval)
      }
    }
    load()
    return () => { alive = false; clearTimeout(timer) }
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

  return <section className="side-question-panel" aria-labelledby="side-question-title">
    <header className="side-question-heading">
      <div className="side-question-title"><MessageOutlined /><h3 id="side-question-title">旁路问答</h3></div>
      {items.length > 0 && <span className="side-question-count">{items.length}</span>}
    </header>
    <p className="side-question-description">基于当前任务快照回答，不影响主任务。</p>
    <div className="side-question-composer">
      <label htmlFor="side-question-input">追问内容</label>
      <Input.TextArea
        id="side-question-input"
        value={question}
        onChange={event => setQuestion(event.target.value)}
        onPressEnter={event => { if (!event.shiftKey) { event.preventDefault(); submit() } }}
        placeholder="输入要追问的问题"
        autoSize={{ minRows: 3, maxRows: 6 }}
        disabled={submitting}
      />
      <div className="side-question-submit"><Button type="primary" icon={<SendOutlined />} loading={submitting} disabled={!question.trim()} onClick={submit}>提问</Button></div>
    </div>
    {(error || loadError) && <div className="side-question-error" role="alert">{error || `问答记录加载失败：${loadError}`}</div>}
    <div className="side-question-history-title">问答记录</div>
    <List
      className="side-question-list"
      loading={loading}
      locale={{ emptyText: loadError ? '正在尝试重新连接…' : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无问答记录" /> }}
      dataSource={items}
      renderItem={item => <List.Item key={item.question_id}>
        <article className="side-question-item">
          <div className="side-question-meta"><Text strong>{item.question}</Text>{statusTag(item.status)}</div>
          <time className="side-question-time">快照 {snapshotTime(item)}</time>
          {(item.answer || item.status === 'running') && <AnswerStream item={item} />}
          {item.error_type && <Text type="danger">{item.error_message || `请求${STATUS_LABELS[item.status]?.[0] || '失败'}，可重新提问。`}</Text>}
          <div className="side-question-actions">
            {ACTIVE_STATUSES.has(item.status) && <Button size="small" icon={<StopOutlined />} loading={busyId === item.question_id} onClick={() => action(item, 'cancel')}>取消</Button>}
            {item.answer && <Button size="small" icon={<ClearOutlined />} loading={busyId === item.question_id} onClick={() => action(item, 'clear')}>清除回答</Button>}
            {item.status === 'running' && <LoadingOutlined spin />}
          </div>
        </article>
      </List.Item>}
    />
  </section>
}

