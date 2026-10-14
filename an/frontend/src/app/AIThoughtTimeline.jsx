import React, { useEffect, useMemo, useState } from 'react'
import { ApiOutlined, BulbOutlined, CheckCircleOutlined, CodeOutlined, DownOutlined, DownloadOutlined, FileTextOutlined, LoadingOutlined, RobotOutlined, SafetyCertificateOutlined, ToolOutlined } from '@ant-design/icons'
import { Button, Empty, Tag } from 'antd'
import { projectThoughtTimeline } from './runtimeModel.js'
import { localizeModelOutput, localizePublicText } from './localization.js'

const icons = { objective: <BulbOutlined />, thought: <RobotOutlined />, model: <CodeOutlined />, tool: <ToolOutlined />, result: <SafetyCertificateOutlined />, conclusion: <FileTextOutlined />, failed: <ApiOutlined /> }

function Usage({ usage }) {
  if (!usage) return null
  return <span className="thought-usage">输入 {usage.prompt_tokens || 0} · 输出 {usage.completion_tokens || 0} · 总计 {usage.total_tokens || ((usage.prompt_tokens || 0) + (usage.completion_tokens || 0))} · 缓存 {usage.cache_read_tokens || 0}</span>
}

function Coverage({ coverage, required = false }) {
  if (!coverage) return required ? <div className="thought-coverage is-missing"><b>缺少覆盖证据</b><span>未记录实际读取的文件，不能证明上传材料已被审计</span></div> : null
  return <div className={`thought-coverage ${coverage.scanned_file_count ? '' : 'is-missing'}`}>
    <b>实际审计覆盖</b>
    <span>{coverage.scanned_file_count || 0} / {coverage.input_file_count || 0} 个文件已读取</span>
    {coverage.skipped_file_count > 0 && <small>{coverage.skipped_file_count} 个不支持或二进制文件未扫描</small>}
  </div>
}

export function AIThoughtTimeline({ events, runStatus, downloadUrl = '' }) {
  const [expanded, setExpanded] = useState(true)
  const [expandedSteps, setExpandedSteps] = useState(() => new Set())
  const timeline = useMemo(() => projectThoughtTimeline(events, runStatus), [events, runStatus])
  const running = !timeline.terminal
  useEffect(() => {
    const active = timeline.items.find((item) => item.active)
    if (active) setExpandedSteps((current) => new Set([...current, active.id]))
  }, [timeline.items])
  function toggleStep(id) {
    setExpandedSteps((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }
  return <div className="ai-thought-view">
    <div className="thought-header">
      <button type="button" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded}>
        <span className={`thought-atom ${running ? 'is-running' : ''}`}>{running ? <LoadingOutlined spin /> : <RobotOutlined />}</span>
        <b>{running ? '思考中' : '已思考'}{timeline.durationSeconds ? `（用时 ${timeline.durationSeconds} 秒）` : ''}</b>
        <DownOutlined className={expanded ? 'is-expanded' : ''} />
      </button>
      <div className="thought-actions"><Tag bordered={false} color={running ? 'processing' : 'success'}>{running ? '实时更新' : '过程已完成'}</Tag>{!running && downloadUrl && <Button size="small" icon={<DownloadOutlined />} href={downloadUrl}>下载思考过程</Button>}</div>
    </div>
    <div className="thought-disclosure">以下为可审计的 AI 摘要、公开模型输出与工具记录，不包含模型隐藏推理。</div>
    {expanded && <div className="thought-timeline">{timeline.items.length ? timeline.items.map((item, index) => <article className={`thought-step is-${item.kind}`} key={item.id}>
      <div className="thought-marker">{icons[item.kind] || <CheckCircleOutlined />}</div>
      {index < timeline.items.length - 1 && <span className="thought-line" />}
      <div className="thought-copy"><header><b>{item.title.replace('planner模型', '规划模型')}</b>{item.agent && <Tag bordered={false}>{item.agent}</Tag>}{item.active && <Tag bordered={false} color="processing">流式生成中</Tag>}</header><p>{item.kind === 'model' ? localizeModelOutput(item.content) : localizePublicText(item.content)}</p>{item.kind === 'thought' && <div className="thought-process"><Button type="text" size="small" onClick={() => toggleStep(item.id)}>{expandedSteps.has(item.id) ? '收起 AI 思考过程' : '展开 AI 思考过程'} <DownOutlined className={expandedSteps.has(item.id) ? 'is-expanded' : ''} /></Button>{expandedSteps.has(item.id) && <div className="thought-process-body">{item.detail && <div className="thought-detail">{localizePublicText(item.detail)}</div>}{item.process?.length ? item.process.map((process) => <section key={process.id} className={`thought-process-stream is-${process.status}`}><header><CodeOutlined /><b>{process.model || 'AI'} · {process.status === 'streaming' ? '正在生成' : '公开输出'}</b></header><pre>{localizeModelOutput(process.content || '模型正在建立响应流…')}{process.status === 'streaming' && <span className="stream-cursor" />}</pre><Usage usage={process.usage} /></section>) : <div className="thought-detail">该步骤没有调用模型，以上为编排器保存的可审计处理说明。</div>}</div>}</div>}{item.kind !== 'thought' && item.detail && <div className="thought-detail">{localizePublicText(item.detail)}</div>}<Coverage coverage={item.coverage} required={item.kind === 'tool'} /><Usage usage={item.usage} /></div>
    </article>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="任务开始后将在此展示 AI 思考摘要" />}</div>}
    {!expanded && <Button type="text" size="small" onClick={() => setExpanded(true)}>展开思考过程</Button>}
  </div>
}
