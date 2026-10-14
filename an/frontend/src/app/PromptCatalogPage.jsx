import React, { useCallback, useEffect, useRef, useState } from 'react'
import { CheckCircleOutlined, FileTextOutlined, ReloadOutlined } from '@ant-design/icons'
import { App, Button, Empty, Input, Modal, Skeleton, Statistic, Tag, Typography } from 'antd'
import { getPrompt, getPromptCatalog, updatePrompt, getPromptHistory } from '../api.js'

const { Text, Title } = Typography
export function PromptCatalogPage() {
  const { message } = App.useApp()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [draft, setDraft] = useState('')
  const [history, setHistory] = useState([])
  const [saving, setSaving] = useState(false)
  const savingRef = useRef(false)
  const mounted = useRef(false)
  const catalogSequence = useRef(0)
  const detailSequence = useRef(0)
  const historySequence = useRef(0)
  const load = useCallback(async () => {
    if (!mounted.current) return
    const sequence = ++catalogSequence.current
    setLoading(true)
    try {
      const catalog = await getPromptCatalog()
      if (sequence === catalogSequence.current) setData(catalog)
    } catch (error) {
      if (sequence === catalogSequence.current) message.error(`读取 Prompt 目录失败：${error.message}`)
    } finally {
      if (sequence === catalogSequence.current) setLoading(false)
    }
  }, [message])
  useEffect(() => {
    mounted.current = true
    load()
    return () => {
      mounted.current = false
      catalogSequence.current += 1
      detailSequence.current += 1
      historySequence.current += 1
    }
  }, [load])

  async function openDetail(prompt) {
    const sequence = ++detailSequence.current
    const historyToken = ++historySequence.current
    setDetail(null)
    setDetailLoading(true)
    try {
      const entry = await getPrompt(prompt.key)
      if (sequence !== detailSequence.current) return
      setDetail(entry); setDraft(entry.content)
      if (entry.runtime_injected) {
        try { const result = await getPromptHistory(entry.key); if (sequence === detailSequence.current && historyToken === historySequence.current) setHistory(result.history || []) }
        catch (error) { if (sequence === detailSequence.current && historyToken === historySequence.current) { setHistory([]); message.warning(`历史版本暂不可用：${error.message}`) } }
      } else setHistory([])
    } catch (error) { if (sequence === detailSequence.current) message.error(`读取 Prompt 详情失败：${error.message}`) }
    finally { if (sequence === detailSequence.current) setDetailLoading(false) }
  }

  async function savePrompt() {
    if (!detail || savingRef.current || draft === detail.content) return
    const key = detail.key
    const content = draft
    const sequence = detailSequence.current
    savingRef.current = true
    setSaving(true)
    let saved
    try {
      saved = await updatePrompt(key, { content, expected_checksum: detail.checksum })
    } catch (error) {
      try {
        const current = await getPrompt(key)
        if (current.content === content) saved = current
      } catch { /* The original request outcome is still unknown. */ }
      if (!saved) {
        message.error(`保存未确认：${error.message}。请刷新详情核对后再编辑。`)
        savingRef.current = false
        setSaving(false)
        return
      }
    }
    const historyToken = ++historySequence.current
    if (sequence === detailSequence.current) {
      setDetail(saved)
      setDraft(saved.content)
    }
    message.success('已保存，新模型调用将使用此版本')
    savingRef.current = false
    setSaving(false)
    load()
    try {
      const result = await getPromptHistory(key)
      if (sequence === detailSequence.current && historyToken === historySequence.current) setHistory(result.history || [])
    } catch (error) {
      if (sequence === detailSequence.current && historyToken === historySequence.current) message.warning(`已保存，历史版本暂未刷新：${error.message}`)
    }
  }

  const closeDetail = () => {
    detailSequence.current += 1
    historySequence.current += 1
    setDetail(null)
    setDetailLoading(false)
  }

  return (
    <div className="catalog-page">
      <section className="page-intro catalog-hero">
        <div>
          <Text className="panel-kicker">PROMPT CATALOG / LOCAL IMPORT</Text>
          <Title level={2}>Prompt 目录</Title>
          <p>编辑当前模型调用阶段的 Prompt，保存后对后续调用生效；调用事件会记录所用版本与哈希。旧协议模板保留为只读参考。</p>
        </div>
        <div className="intro-tags"><Button type="text" icon={<ReloadOutlined />} onClick={load}>刷新</Button></div>
      </section>
      <section className="catalog-metrics">
        <div className="catalog-metric"><FileTextOutlined /><Statistic title="已登记模板" value={data?.count ?? 0} /></div>
        <div className="catalog-metric"><CheckCircleOutlined /><Statistic title="来源" value="本地目录" /></div>
      </section>
      <section className="glass-panel catalog-library">
        <header className="panel-heading">
          <div><Text className="panel-kicker">BUNDLED ASSETS</Text><Title level={4}>角色与阶段</Title></div>
          <Tag>{data?.schema_version || '1.0'}</Tag>
        </header>
        <div className="prompt-grid">
          {loading ? <Skeleton active paragraph={{ rows: 8 }} /> : data?.prompts?.length ? data.prompts.map((prompt) => (
            <article
              className="prompt-card prompt-card-action"
              role="button"
              tabIndex={0}
              key={prompt.key}
              onClick={() => openDetail(prompt)}
              onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') openDetail(prompt) }}
            >
              <div className="prompt-card-icon"><FileTextOutlined /></div>
              <div className="prompt-card-main">
                <header><div><b>{prompt.name}</b><small>{prompt.key} · {prompt.version || '未标注版本'}</small></div><Tag color={prompt.runtime_injected ? 'green' : 'default'}>{prompt.runtime_injected ? '已接入 · ' : '参考 · '}{prompt.stage}</Tag></header>
                <p>{prompt.purpose}</p>
                <footer><span>{prompt.category}</span><code>SHA {String(prompt.checksum).slice(0, 12)}…</code></footer>
              </div>
            </article>
          )) : <Empty description="暂无 Prompt 资产" />}
        </div>
      </section>
      <Modal
        open={Boolean(detail) || detailLoading}
        title={detail?.name || 'Prompt 详情'}
        footer={<Button onClick={closeDetail}>关闭</Button>}
        width={780}
        onCancel={closeDetail}
        confirmLoading={detailLoading}
      >
        <div className="prompt-detail">
          {detail ? (
            <>
              <div className="prompt-detail-meta"><Tag>{detail.key}</Tag><Tag>{detail.stage}</Tag><Tag>{detail.version || '未标注版本'}</Tag><span>{detail.purpose}</span></div>
              <dl><div><dt>来源</dt><dd>{detail.source}</dd></div><div><dt>校验和</dt><dd>{detail.checksum}</dd></div><div><dt>大小</dt><dd>{detail.size_bytes} bytes</dd></div></dl>
              {detail.runtime_injected ? (
                <>
                  <Input.TextArea aria-label="运行 Prompt 内容" rows={12} value={draft} disabled={saving} onChange={event => setDraft(event.target.value)} />
                  <Button type="primary" style={{ marginTop: 12 }} loading={saving} disabled={draft === detail.content} onClick={savePrompt}>保存并用于后续调用</Button>
                  <details><summary>历史版本（点击填入编辑器，保存后生效）</summary>{history.map((entry, index) => <Button key={`${entry.version}-${index}`} disabled={saving} onClick={() => setDraft(entry.content)}>{entry.version}</Button>)}</details>
                </>
              ) : <pre>{detail.content}</pre>}
            </>
          ) : <Skeleton active paragraph={{ rows: 12 }} />}
        </div>
      </Modal>
    </div>
  )
}
