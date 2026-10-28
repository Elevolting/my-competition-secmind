import React, { useMemo, useState } from 'react'
import { Alert, Input, Modal, Statistic, Table, Tag } from 'antd'
import { parseLogAnalysis } from './logAnalysisModel.js'
import { EvidenceFields, EvidenceRawDetails, EvidenceSourceFields } from './EvidenceDrawer.jsx'
import { eventSources, resolveReference, sourceReferenceKey } from './evidenceInspectionModel.js'
import './LogAnalysisPanel.css'

/** @typedef {import('./logAnalysisModel.js').LogAnalysisReport} LogAnalysisReport */
/** @typedef {import('./logAnalysisModel.js').LogEvent} LogEvent */
/** @typedef {import('./logAnalysisModel.js').LogIoc} LogIoc */
/** @typedef {import('./logAnalysisModel.js').LogRuleMatch} LogRuleMatch */
/** @typedef {import('./logAnalysisModel.js').LogSource} LogSource */
/** @typedef {{ kind: 'event', eventId: string } | { kind: 'source', sourceKey: string }} LogSelection */
/** @typedef {{ onEvidenceSelect: ((id: string) => void) | undefined, onEventSelect: (id: string) => void, onSourceSelect: (source: LogSource) => void }} Navigation */

/** @param {{ ids: string[], onSelect: ((id: string) => void) | undefined, testId: string, label: string }} props @returns {React.ReactNode} */
function References({ ids, onSelect, testId, label }) {
  return ids.length ? ids.map((id, index) => onSelect ? <button type="button" className="log-analysis-reference log-analysis-link"
    data-testid={testId} data-reference-id={id} aria-label={`${label} ${id}`} key={`${id}:${index}`} onClick={() => onSelect(id)}>{id}</button>
    : <code className="log-analysis-reference" key={`${id}:${index}`}>{id}</code>) : '—'
}

/** @param {import('./logAnalysisModel.js').LogSourceLocator | null} locator @returns {React.ReactNode} */
function locationText(locator) {
  if (locator === null) return '—'
  return <span>{locator.source_ref}<small className="log-analysis-reference">行 {locator.line_number ?? '—'} · 记录 {locator.record_number ?? '—'} · 字节 {locator.byte_offset ?? '—'} / {locator.byte_length ?? '—'}</small></span>
}

/** @param {Navigation} navigation */
function logColumns({ onEvidenceSelect, onEventSelect, onSourceSelect }) {
  /** @param {string[]} ids @returns {React.ReactNode} */
  const evidenceReferences = (ids) => <References ids={ids} onSelect={onEvidenceSelect} testId="log-evidence-reference" label="查看证据" />
  /** @param {string[]} ids @returns {React.ReactNode} */
  const eventReferences = (ids) => <References ids={ids} onSelect={onEventSelect} testId="log-event-reference" label="查看事件" />
  /** @type {import('antd').TableProps<LogEvent>['columns']} */
  const events = [
    { title: '时间 / 事件', width: 230, render: (_, row) => <span>{row.timestamp ?? '—'}<small className="log-analysis-reference">{row.event_type}</small>{eventReferences([row.event_id])}</span> },
    { title: '级别', dataIndex: 'severity', width: 110, render: (value) => value === null ? '—' : <Tag>{value}</Tag> },
    { title: '日志内容', dataIndex: 'message', width: 330, render: (value) => <span className="log-analysis-text">{value}</span> },
    { title: '定位 / 证据', width: 280, render: (_, row) => <>{row.source_locator === null ? '—' : <button type="button"
      className="log-analysis-link" data-testid="log-event-source-reference" aria-label={`查看事件来源 ${row.event_id}`}
      onClick={() => onEventSelect(row.event_id)}>{locationText(row.source_locator)}</button>}{evidenceReferences(row.evidence_ids)}</> },
  ]
  /** @type {import('antd').TableProps<LogIoc>['columns']} */
  const iocs = [
    { title: '类型', dataIndex: 'ioc_type', width: 130 },
    { title: 'IOC', dataIndex: 'value', width: 300, render: (value) => <code className="log-analysis-text">{value}</code> },
    { title: '关联事件', dataIndex: 'event_id', width: 240, render: (value) => value === null ? '—' : eventReferences([value]) },
    { title: '证据', dataIndex: 'evidence_ids', width: 260, render: evidenceReferences },
  ]
  /** @type {import('antd').TableProps<LogRuleMatch>['columns']} */
  const rules = [
    { title: '规则', width: 300, render: (_, row) => <span>{row.title}<code className="log-analysis-reference">{row.rule_id}</code></span> },
    { title: '级别', dataIndex: 'severity', width: 110, render: (value) => <Tag>{value}</Tag> },
    { title: '命中事件', dataIndex: 'event_ids', width: 260, render: eventReferences },
    { title: '证据', dataIndex: 'evidence_ids', width: 260, render: evidenceReferences },
  ]
  /** @type {import('antd').TableProps<LogSource>['columns']} */
  const sources = [
    { title: '来源', dataIndex: 'source_ref', width: 230, render: (value, row) => <button type="button" className="log-analysis-link"
      data-testid="log-source-reference" data-evidence-id={row.evidence_id} aria-label={`查看来源 ${value} · ${row.evidence_id}`}
      onClick={() => onSourceSelect(row)}>{value}</button> },
    { title: '行 / 记录', width: 130, render: (_, row) => `${row.line_number ?? '—'} / ${row.record_number ?? '—'}` },
    { title: '证据 ID', dataIndex: 'evidence_id', width: 260, render: (value) => evidenceReferences([value]) },
    { title: 'SHA-256', dataIndex: 'sha256', width: 340, render: (value) => <code className="log-analysis-text">{value ?? '—'}</code> },
  ]
  return { events, iocs, rules, sources }
}

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

/** @param {{ event: LogEvent, data: LogAnalysisReport, onEvidenceSelect: ((id: string) => void) | undefined, sourceColumns: import('antd').TableProps<LogSource>['columns'] }} props @returns {React.ReactNode} */
function EventDetails({ event, data, onEvidenceSelect, sourceColumns }) {
  const locator = event.source_locator
  const sources = eventSources(event, data.sources)
  return <div data-testid="log-event-detail" className="evidence-inspection">
    <EvidenceFields fields={[
      ['事件 ID', event.event_id], ['时间', event.timestamp ?? '未记录'], ['事件类型', event.event_type],
      ['级别', event.severity ?? '未记录'], ['日志内容', event.message],
      ['证据 ID', <References ids={event.evidence_ids} onSelect={onEvidenceSelect} testId="log-evidence-reference" label="查看证据" />],
    ]} />
    <h4>来源定位</h4>
    {locator === null ? <p>事件未记录 source_locator。</p> : <EvidenceFields fields={[
      ['来源引用', locator.source_ref], ['行号', locator.line_number ?? '未记录'], ['记录号', locator.record_number ?? '未记录'],
      ['字节偏移', locator.byte_offset ?? '未记录'], ['字节长度', locator.byte_length ?? '未记录'],
    ]} />}
    {sources.length ? <LogTable title="匹配的来源记录" testId="log-event-source-matches" rows={sources} columns={sourceColumns} query="" />
      : <Alert type="warning" showIcon title="未找到来源记录" data-testid="log-source-missing"
        description={locator === null ? '事件没有来源定位，不能推断来源。' : 'report.log_analysis.sources 中没有与此来源引用及已记录行号/记录号一致的记录。'} />}
    <EvidenceRawDetails value={event} />
  </div>
}

/** @param {{ selection: LogSelection | null, data: LogAnalysisReport, onClose: () => void, onEvidenceSelect: ((id: string) => void) | undefined, sourceColumns: import('antd').TableProps<LogSource>['columns'] }} props @returns {React.ReactNode} */
function LogNavigationDetails({ selection, data, onClose, onEvidenceSelect, sourceColumns }) {
  const result = useMemo(() => {
    if (selection === null) return null
    try {
      return selection.kind === 'event'
        ? { event: resolveReference(data.events, (row) => row.event_id, selection.eventId, 'report.log_analysis.events'), source: null, error: null }
        : { event: null, source: resolveReference(data.sources, sourceReferenceKey, selection.sourceKey, 'report.log_analysis.sources'), error: null }
    } catch (cause) {
      if (!(cause instanceof TypeError)) throw cause
      return { event: null, source: null, error: cause.message }
    }
  }, [selection, data])
  return <Modal open={selection !== null} title={selection?.kind === 'source' ? '日志来源详情' : '日志事件详情'} onCancel={onClose}
    footer={null} width={900} destroyOnHidden data-testid="log-navigation-modal">
    {selection !== null && (result?.error ? <Alert type="error" showIcon title={selection.kind === 'source' ? '来源引用无效' : '事件引用无效'}
      description={result.error} data-testid={selection.kind === 'source' ? 'log-source-invalid' : 'log-event-invalid'} />
      : selection.kind === 'source' ? result?.source ? <div data-testid="log-source-detail" className="evidence-inspection">
        <EvidenceSourceFields source={result.source} evidenceLink={<References ids={[result.source.evidence_id]}
          onSelect={onEvidenceSelect} testId="log-evidence-reference" label="查看证据" />} />
        <EvidenceRawDetails value={result.source} />
      </div> : <Alert type="warning" showIcon title="未找到来源记录"
        description={`report.log_analysis.sources 中不存在来源引用 ${selection.sourceKey}。`} data-testid="log-source-missing" />
        : result?.event ? <EventDetails event={result.event} data={data} onEvidenceSelect={onEvidenceSelect} sourceColumns={sourceColumns} />
          : <Alert type="warning" showIcon title="未找到事件" description={`report.log_analysis.events 中不存在引用 ${selection.eventId}。`}
            data-testid="log-event-missing" />)}
  </Modal>
}

/** @param {{ value: import('./logAnalysisModel.js').JsonValue | undefined, onEvidenceSelect?: (id: string) => void }} props @returns {React.ReactNode} */
export function LogAnalysisPanel({ value, onEvidenceSelect }) {
  const [query, setQuery] = useState('')
  /** @type {[LogSelection | null, React.Dispatch<React.SetStateAction<LogSelection | null>>]} */
  const [selection, setSelection] = useState(null)
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
  /** @type {((id: string) => void) | undefined} */
  const selectEvidence = onEvidenceSelect === undefined ? undefined : (id) => {
    setSelection(null)
    onEvidenceSelect(id)
  }
  const columns = logColumns({ onEvidenceSelect: selectEvidence,
    onEventSelect: (eventId) => setSelection({ kind: 'event', eventId }),
    onSourceSelect: (source) => setSelection({ kind: 'source', sourceKey: sourceReferenceKey(source) }),
  })
  const search = query.trim().toLocaleLowerCase()
  return <section data-testid="log-analysis-panel" className="log-analysis-panel" aria-label="日志分析">
    <header><h3>日志分析</h3><Input.Search aria-label="搜索日志分析内容" data-testid="log-analysis-search" placeholder="搜索事件、IOC、规则或证据" allowClear value={query} onChange={(event) => setQuery(event.target.value)} /></header>
    <div className="log-analysis-statistics">{[
      ['处理来源', data.statistics.sources_processed], ['输入记录', data.statistics.input_records], ['已解析', data.statistics.parsed_records],
      ['拒绝记录', data.statistics.rejected_records], ['移除重复', data.statistics.duplicates_removed],
    ].map(([label, count]) => <div key={label}><Statistic title={label} value={count ?? '—'} /></div>)}</div>
    <LogTable title="事件时间线" testId="log-analysis-events" rows={data.events} columns={columns.events} query={search} />
    <LogTable title="IOC" testId="log-analysis-iocs" rows={data.iocs} columns={columns.iocs} query={search} />
    <LogTable title="规则命中" testId="log-analysis-rules" rows={data.rule_matches} columns={columns.rules} query={search} />
    <LogTable title="来源证据" testId="log-analysis-sources" rows={data.sources} columns={columns.sources} query={search} />
    <LogNavigationDetails selection={selection} data={data} onClose={() => setSelection(null)} onEvidenceSelect={selectEvidence} sourceColumns={columns.sources} />
  </section>
}
