import React, { useMemo, useState } from 'react'
import { Alert, Input, Statistic, Table, Tag } from 'antd'
import { parseLogAnalysis } from './logAnalysisModel.js'
import './LogAnalysisPanel.css'

/** @typedef {import('./logAnalysisModel.js').LogAnalysisReport} LogAnalysisReport */
/** @typedef {import('./logAnalysisModel.js').LogEvent} LogEvent */
/** @typedef {import('./logAnalysisModel.js').LogIoc} LogIoc */
/** @typedef {import('./logAnalysisModel.js').LogRuleMatch} LogRuleMatch */
/** @typedef {import('./logAnalysisModel.js').LogSource} LogSource */

/** @param {string[]} ids @returns {React.ReactNode} */
function references(ids) {
  return ids.length ? ids.map((id, index) => <code className="log-analysis-reference" key={`${id}:${index}`}>{id}</code>) : '—'
}

/** @param {import('./logAnalysisModel.js').LogSourceLocator | null} locator @returns {React.ReactNode} */
function locationText(locator) {
  if (locator === null) return '—'
  return <span>{locator.source_ref}<small className="log-analysis-reference">行 {locator.line_number ?? '—'} · 记录 {locator.record_number ?? '—'} · 字节 {locator.byte_offset ?? '—'} / {locator.byte_length ?? '—'}</small></span>
}

/** @type {import('antd').TableProps<LogEvent>['columns']} */
const eventColumns = [
  { title: '时间 / 事件', width: 230, render: (_, row) => <span>{row.timestamp ?? '—'}<small className="log-analysis-reference">{row.event_type}</small><code className="log-analysis-reference">{row.event_id}</code></span> },
  { title: '级别', dataIndex: 'severity', width: 110, render: (value) => value === null ? '—' : <Tag>{value}</Tag> },
  { title: '日志内容', dataIndex: 'message', width: 330, render: (value) => <span className="log-analysis-text">{value}</span> },
  { title: '定位 / 证据', width: 280, render: (_, row) => <>{locationText(row.source_locator)}{references(row.evidence_ids)}</> },
]
/** @type {import('antd').TableProps<LogIoc>['columns']} */
const iocColumns = [
  { title: '类型', dataIndex: 'ioc_type', width: 130 },
  { title: 'IOC', dataIndex: 'value', width: 300, render: (value) => <code className="log-analysis-text">{value}</code> },
  { title: '关联事件', dataIndex: 'event_id', width: 240, render: (value) => value ?? '—' },
  { title: '证据', dataIndex: 'evidence_ids', width: 260, render: references },
]
/** @type {import('antd').TableProps<LogRuleMatch>['columns']} */
const ruleColumns = [
  { title: '规则', width: 300, render: (_, row) => <span>{row.title}<code className="log-analysis-reference">{row.rule_id}</code></span> },
  { title: '级别', dataIndex: 'severity', width: 110, render: (value) => <Tag>{value}</Tag> },
  { title: '命中事件', dataIndex: 'event_ids', width: 260, render: references },
  { title: '证据', dataIndex: 'evidence_ids', width: 260, render: references },
]
/** @type {import('antd').TableProps<LogSource>['columns']} */
const sourceColumns = [
  { title: '来源', dataIndex: 'source_ref', width: 230 },
  { title: '行 / 记录', width: 130, render: (_, row) => `${row.line_number ?? '—'} / ${row.record_number ?? '—'}` },
  { title: '证据 ID', dataIndex: 'evidence_id', width: 260 },
  { title: 'SHA-256', dataIndex: 'sha256', width: 340, render: (value) => <code className="log-analysis-text">{value ?? '—'}</code> },
]

/**
 * @template {LogEvent | LogIoc | LogRuleMatch | LogSource} T
 * @param {{ title: string, testId: string, rows: T[], columns: import('antd').TableProps<T>['columns'], query: string }} props
 * @returns {React.ReactNode}
 */
function LogTable({ title, testId, rows, columns, query }) {
  const filtered = rows.filter((row) => JSON.stringify(row).toLocaleLowerCase().includes(query))
  return <section data-testid={testId} className="log-analysis-section" aria-label={title}>
    <h4>{title} · {filtered.length}{query ? ` / ${rows.length}` : ''}</h4>
    <Table key={query} size="small" dataSource={filtered} columns={columns} rowKey={(row) => JSON.stringify(row)} scroll={{ x: 900 }}
      pagination={{ pageSize: 10, showSizeChanger: false, showTotal: (total) => `共 ${total} 条` }} locale={{ emptyText: query ? '没有匹配记录' : '暂无记录' }} />
  </section>
}

/** @param {{ value: import('./logAnalysisModel.js').JsonValue | undefined }} props @returns {React.ReactNode} */
export function LogAnalysisPanel({ value }) {
  const [query, setQuery] = useState('')
  const result = useMemo(() => {
    try { return { data: parseLogAnalysis(value), error: null } }
    catch (cause) {
      if (!(cause instanceof TypeError)) throw cause
      return { data: null, error: cause.message }
    }
  }, [value])
  if (result.error) return <section data-testid="log-analysis-panel"><Alert type="error" showIcon title="日志分析数据无效" description={result.error} /></section>
  const data = result.data
  if (data === null) return null
  const search = query.trim().toLocaleLowerCase()
  return <section data-testid="log-analysis-panel" className="log-analysis-panel" aria-label="日志分析">
    <header><h3>日志分析</h3><Input.Search aria-label="搜索日志分析内容" data-testid="log-analysis-search" placeholder="搜索事件、IOC、规则或证据" allowClear value={query} onChange={(event) => setQuery(event.target.value)} /></header>
    <div className="log-analysis-statistics">{[
      ['处理来源', data.statistics.sources_processed], ['输入记录', data.statistics.input_records], ['已解析', data.statistics.parsed_records],
      ['拒绝记录', data.statistics.rejected_records], ['移除重复', data.statistics.duplicates_removed],
    ].map(([label, count]) => <div key={label}><Statistic title={label} value={count ?? '—'} /></div>)}</div>
    <LogTable title="事件时间线" testId="log-analysis-events" rows={data.events} columns={eventColumns} query={search} />
    <LogTable title="IOC" testId="log-analysis-iocs" rows={data.iocs} columns={iocColumns} query={search} />
    <LogTable title="规则命中" testId="log-analysis-rules" rows={data.rule_matches} columns={ruleColumns} query={search} />
    <LogTable title="来源证据" testId="log-analysis-sources" rows={data.sources} columns={sourceColumns} query={search} />
  </section>
}
