import React from 'react'
import { Button, Empty, Modal } from 'antd'
import { ACTIVE, STATUS, isIntent } from './executionCanvasModel.js'
import { StatusBadge, nodeKind } from './ExecutionNodeCard.jsx'

const Section = ({ title, children }) => <section className="execution-detail-section"><h4>{title}</h4>{children}</section>
const time = (value) => value ? new Date(value).toLocaleTimeString('zh-CN', { hour12: false }) : '未记录时间'

export default function ExecutionDetails({ node, graph, expanded, toggleBundle, focus, elapsed }) {
  if (!node) return <div className="execution-detail-empty"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="选择一个想法，查看依据与证据" /></div>
  const intent = isIntent(node)
  return <div className="execution-detail-scroll">
    <div className="execution-detail-top"><span>{nodeKind(node)}</span><code title={node.raw_id}>{node.raw_id}</code></div>
    <h3>{node.title || node.label}</h3><StatusBadge status={node.status} />
    {(!intent || node.summary) && <p className="execution-detail-lead">{node.summary || node.title || node.description}</p>}
    {intent ? <>
      <Section title="验证目标"><p>{node.description || '未记录验证目标'}</p></Section>
      <Section title="基于哪些事实">{node.source_links?.length ? node.source_links.map((source) => <button className="execution-source-reference" key={source.fact_id} onClick={() => focus(graph.nodes.find((item) => item.raw_id === source.fact_id)?.id || `fact:${source.fact_id}`)}>
        {graph.nodes.find((item) => item.raw_id === source.fact_id)?.title || source.fact_id}
        <small>{source.fact_id} · {{ evidence: '引用事实', process: '流程衔接', unknown: '来源不明' }[source.relation] || '来源不明'}</small>
      </button>) : <p>来源不明 · 未记录明确的引用事实</p>}</Section>
      <Section title="成功条件"><p>{node.success_criteria || '未记录成功条件'}</p></Section>
      <Section title="当前执行"><dl className="execution-meta">
        <dt>Worker</dt><dd>{node.worker || '未领取'}</dd>
        <dt>当前动作</dt><dd className={ACTIVE.has(node.status) ? 'is-live' : ''}>{node.current_tool || (ACTIVE.has(node.status) ? '执行中，暂无工具记录' : '无进行中的工具')}</dd>
        <dt>执行阶段</dt><dd>{node.phase || '未记录阶段'}</dd>
        <dt>耗时</dt><dd>{elapsed(node) || '未记录'}</dd>
        <dt>执行尝试</dt><dd><code>{node.attempt_id || '历史任务未记录'}</code></dd>
        <dt>最近活动</dt><dd>{time(node.latest_activity)}</dd>
      </dl></Section>
      <Section title="执行记录（含历史尝试）">{node.execution_history?.length ? <ol className="execution-timeline">{node.execution_history.map((item, index) => <li className={index === node.execution_history.length - 1 && ACTIVE.has(node.status) ? 'active' : ''} key={item.event_id || index}>
        <span>{item.tool || item.phase || item.event_type?.replace('runtime.', '')} · {STATUS[item.status] || item.status || item.event_type?.split('.').at(-1)}</span>
        <time>{time(item.timestamp)} · {item.attempt_id || '历史记录'}</time>
      </li>)}</ol> : <p>暂无执行事件</p>}</Section>
    </> : <>
      {node.legacy && <p className="execution-legacy">历史原文 · 无结构化证据的陈述属于 Worker 报告</p>}
      {node.items?.length > 0 && <Section title={<span className="execution-bundle-heading">结果条目 · {node.items.length}<Button size="small" onClick={() => toggleBundle(node.id)}>{expanded.has(node.id) ? '收起' : '展开到画布'}</Button></span>}>
        {node.items.map((item) => <button className="execution-result-item" key={item.id} onClick={() => { if (!expanded.has(node.id)) toggleBundle(node.id); setTimeout(() => focus(`item:${node.raw_id}:${item.id}`), 0) }}>
          <strong>{item.title}</strong><small>{item.summary}</small><span>{item.verification_status ? STATUS[item.verification_status] || item.verification_status : item.evidence_ids?.length ? `${item.evidence_ids.length} 条证据` : 'Worker 报告'}</span>
        </button>)}
      </Section>}
      {node.producers?.length > 0 && <Section title="来源想法">{node.producers.map((producer) => <button className="execution-source-reference" key={producer.id} onClick={() => focus(producer.id)}>{producer.title}<small>{producer.raw_id} · 验证产出</small></button>)}</Section>}
      {node.parent_fact_id && <Section title="来源结果包"><p>{node.parent_fact_id}</p></Section>}
      {node.evidence_ids?.length > 0 && <Section title="证据引用">{node.evidence_ids.map((id) => <div className="execution-evidence" key={id}>
        <b>{id}</b><small>关联此结论的原始记录</small><Button size="small" onClick={() => {
          const evidence = node.evidence?.find((item) => item.evidence_id === id)
          Modal.info({ title: `证据 ${id}`, width: 680, content: <pre className="execution-evidence-output">{evidence ? JSON.stringify(evidence, null, 2) : '历史证据引用；当前任务中未找到证据内容'}</pre> })
        }}>查看证据 {id}</Button>
      </div>)}</Section>}
      {node.provenance && <Section title="记录来源"><p>{node.provenance}</p></Section>}
      <Section title="原始输出"><details className="execution-raw"><summary>展开原始记录</summary><pre>{node.description || node.summary || '未记录'}</pre></details></Section>
    </>}
  </div>
}
