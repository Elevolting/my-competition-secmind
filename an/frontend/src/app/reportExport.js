import { parseLogAnalysis } from './logAnalysisModel.js'

/**
 * Public export subsets of AgentReport, Finding, Evidence, RunSummary,
 * TaskRequest/task settings, and RetestStore._public. Opaque raw/metadata,
 * artifact bodies, attachments and execution/configuration objects are excluded.
 * Optional arrays correspond to schema defaults and older persisted reports.
 * @typedef {'pending' | 'running' | 'waiting_approval' | 'completed' | 'partial' | 'denied' | 'failed'} ReportStatus
 * @typedef {'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'} FindingSeverity
 * @typedef {'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN'} FindingConfidence
 * @typedef {{ finding_id: string, rule_id: string, severity: FindingSeverity, confidence: FindingConfidence, path: string, line?: number | null, title: string, description: string, remediation?: string | null, evidence_ids?: string[] }} ReportFinding
 * @typedef {{ evidence_id: string, source: string, summary: string, sha256?: string | null }} ReportEvidence
 * @typedef {{ retest_id: string, source_run_id: string, source_kind: string, source_ref: string, child_run_id: string, status: string, verdict: string | null, summary: string | null, original_evidence_ids: string[], evidence_ids: string[], error: string | null, created_at: string, started_at: string | null, finished_at: string | null }} ReportRetest
 * @typedef {{ run_id: string, status: ReportStatus, executive_summary: string, generated_at?: string, findings?: ReportFinding[], confirmed_findings?: ReportFinding[], candidate_findings?: ReportFinding[], evidence?: ReportEvidence[], verified_outputs?: string[], limitations?: string[], ruled_out_directions?: string[], insufficient_evidence?: string[], worker_reports?: string[], log_analysis?: import('./logAnalysisModel.js').LogAnalysisReport | null, retests?: ReportRetest[] }} ExportReportInput
 * @typedef {{ run_id: string, name?: string | null, objective?: string, target_scope?: string[] }} ExportRunInput
 * @typedef {{ label: string, value: string }} ReportField
 * @typedef {{ title: string, fields: ReportField[] }} ReportEntry
 * @typedef {{ title: string, entries: ReportEntry[] }} ReportSection
 * @typedef {{ title: string, filenameStem: string, sections: ReportSection[] }} ReportDocument
 * @typedef {{ filename: string, mimeType: string, content: string }} ReportDownload
 * @typedef {{ markdown: ReportDownload, html: ReportDownload }} ReportDownloads
 */

/** @template T @param {T} value @param {string} path @returns {T} */
function objectValue(value, path) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${path} 必须是对象；请刷新报告后重试`)
  return value
}

/** @param {string} value @param {string} path @returns {string} */
function textValue(value, path) {
  if (typeof value !== 'string') throw new TypeError(`${path} 必须是字符串；请刷新报告后重试`)
  return value
}

/** @template T @param {T[] | undefined} value @param {string} path @returns {T[]} */
function arrayValue(value, path) {
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new TypeError(`${path} 必须是数组；请刷新报告后重试`)
  return value
}

/** @param {string[] | undefined} value @param {string} path @returns {string[]} */
function stringsValue(value, path) {
  return arrayValue(value, path).map((item, index) => textValue(item, `${path}[${index}]`))
}

/** @param {string} label @param {string} value @param {string} path @returns {ReportField} */
function field(label, value, path) {
  return { label, value: textValue(value, path) }
}

/** @param {string} label @param {string | null | undefined} value @param {string} path @returns {ReportField[]} */
function optionalField(label, value, path) {
  return value === null || value === undefined ? [] : [field(label, value, path)]
}

/** @param {string} label @param {string[] | undefined} value @param {string} path @returns {ReportField} */
function idsField(label, value, path) {
  return { label, value: stringsValue(value, path).join('\n') || '无' }
}

/** @param {string} label @param {number | null | undefined} value @param {string} path @returns {ReportField[]} */
function countField(label, value, path) {
  if (value === undefined || value === null) return []
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${path} 必须是非负安全整数或 null`)
  return [{ label, value: String(value) }]
}

/** @param {ReportFinding} value @param {string} path @returns {ReportFinding} */
function findingValue(value, path) {
  const row = objectValue(value, path)
  const severity = textValue(row.severity, `${path}.severity`)
  const confidence = textValue(row.confidence, `${path}.confidence`)
  if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'].includes(severity)) throw new TypeError(`${path}.severity 无效`)
  if (!['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'].includes(confidence)) throw new TypeError(`${path}.confidence 无效`)
  countField('行号', row.line, `${path}.line`)
  const remediation = optionalField('修复建议', row.remediation, `${path}.remediation`)
  const findingId = textValue(row.finding_id, `${path}.finding_id`)
  if (!findingId.trim()) throw new TypeError(`${path}.finding_id 不能为空；无法安全合并报告分区`)
  return {
    finding_id: findingId, rule_id: textValue(row.rule_id, `${path}.rule_id`),
    severity: /** @type {FindingSeverity} */ (severity), confidence: /** @type {FindingConfidence} */ (confidence),
    path: textValue(row.path, `${path}.path`), line: row.line,
    title: textValue(row.title, `${path}.title`), description: textValue(row.description, `${path}.description`),
    remediation: remediation.length ? remediation[0].value : null, evidence_ids: stringsValue(row.evidence_ids, `${path}.evidence_ids`),
  }
}

/** @param {ReportFinding} finding @param {number} index @returns {ReportEntry} */
function findingEntry(finding, index) {
  return { title: `发现 ${index + 1}`, fields: [
    { label: '标题', value: finding.title }, { label: '发现 ID', value: finding.finding_id }, { label: '规则 ID', value: finding.rule_id },
    { label: '严重性', value: finding.severity }, { label: '置信度', value: finding.confidence }, { label: '位置', value: finding.path },
    ...countField('行号', finding.line, 'finding.line'), { label: '描述', value: finding.description },
    ...optionalField('修复建议', finding.remediation, 'finding.remediation'), idsField('证据 ID', finding.evidence_ids, 'finding.evidence_ids'),
  ] }
}

/** @param {ReportEvidence} value @param {number} index @returns {ReportEntry} */
function evidenceEntry(value, index) {
  const path = `report.evidence[${index}]`
  const row = objectValue(value, path)
  return { title: `证据 ${index + 1}`, fields: [field('证据 ID', row.evidence_id, `${path}.evidence_id`),
    field('来源', row.source, `${path}.source`), field('摘要', row.summary, `${path}.summary`),
    ...optionalField('SHA-256', row.sha256, `${path}.sha256`)] }
}

/** @param {ReportRetest} value @param {number} index @returns {ReportEntry} */
function retestEntry(value, index) {
  const path = `report.retests[${index}]`
  const row = objectValue(value, path)
  for (const key of ['verdict', 'summary', 'error', 'original_evidence_ids', 'evidence_ids', 'started_at', 'finished_at']) {
    if (!Object.hasOwn(row, key)) throw new TypeError(`${path}.${key} 是必需字段；请刷新报告后重试`)
  }
  return { title: `独立复核 ${index + 1}`, fields: [
    field('复核 ID', row.retest_id, `${path}.retest_id`), field('来源任务 ID', row.source_run_id, `${path}.source_run_id`),
    field('原对象类型', row.source_kind, `${path}.source_kind`), field('原对象引用', row.source_ref, `${path}.source_ref`),
    field('复核任务 ID', row.child_run_id, `${path}.child_run_id`), field('状态', row.status, `${path}.status`),
    ...optionalField('结论', row.verdict, `${path}.verdict`), ...optionalField('结论摘要', row.summary, `${path}.summary`),
    idsField('原证据 ID', row.original_evidence_ids, `${path}.original_evidence_ids`), idsField('本次证据 ID', row.evidence_ids, `${path}.evidence_ids`),
    ...optionalField('错误', row.error, `${path}.error`), field('创建时间', row.created_at, `${path}.created_at`),
    ...optionalField('开始时间', row.started_at, `${path}.started_at`), ...optionalField('完成时间', row.finished_at, `${path}.finished_at`),
  ] }
}

/** @param {string} title @param {string[] | undefined} values @param {string} path @returns {ReportSection[]} */
function textSection(title, values, path) {
  const entries = stringsValue(values, path).map((value, index) => ({ title: `条目 ${index + 1}`, fields: [{ label: '内容', value }] }))
  return entries.length ? [{ title, entries }] : []
}

/** @param {import('./logAnalysisModel.js').LogAnalysisReport | null | undefined} value @returns {ReportSection[]} */
function logSections(value) {
  const log = parseLogAnalysis(value)
  if (!log) return []
  const stats = log.statistics
  return [
    { title: '日志分析 · 统计', entries: [{ title: '处理统计', fields: [
      { label: '来源数', value: stats.sources_processed === null ? '未知' : String(stats.sources_processed) },
      { label: '输入记录', value: stats.input_records === null ? '未知' : String(stats.input_records) },
      { label: '有效记录', value: stats.parsed_records === null ? '未知' : String(stats.parsed_records) },
      { label: '拒绝记录', value: stats.rejected_records === null ? '未知' : String(stats.rejected_records) },
      { label: '去重记录', value: stats.duplicates_removed === null ? '未知' : String(stats.duplicates_removed) },
    ] }] },
    { title: '日志分析 · 事件', entries: log.events.map((event, index) => ({ title: `事件 ${index + 1}`, fields: [
      { label: '事件 ID', value: event.event_id }, ...optionalField('时间', event.timestamp, 'event.timestamp'),
      { label: '事件类型', value: event.event_type }, ...optionalField('严重性', event.severity, 'event.severity'),
      { label: '消息', value: event.message }, idsField('证据 ID', event.evidence_ids, 'event.evidence_ids'),
      ...(event.source_locator ? [
        { label: '来源引用', value: event.source_locator.source_ref },
        ...countField('行号', event.source_locator.line_number, 'locator.line_number'),
        ...countField('记录号', event.source_locator.record_number, 'locator.record_number'),
        ...countField('字节偏移', event.source_locator.byte_offset, 'locator.byte_offset'),
        ...countField('字节长度', event.source_locator.byte_length, 'locator.byte_length'),
      ] : []),
    ] })) },
    { title: '日志分析 · IOC', entries: log.iocs.map((ioc, index) => ({ title: `IOC ${index + 1}`, fields: [
      { label: '类型', value: ioc.ioc_type }, { label: '值', value: ioc.value }, ...optionalField('事件 ID', ioc.event_id, 'ioc.event_id'),
      idsField('证据 ID', ioc.evidence_ids, 'ioc.evidence_ids'),
    ] })) },
    { title: '日志分析 · 规则命中', entries: log.rule_matches.map((rule, index) => ({ title: `规则 ${index + 1}`, fields: [
      { label: '规则 ID', value: rule.rule_id }, { label: '标题', value: rule.title }, { label: '严重性', value: rule.severity },
      idsField('事件 ID', rule.event_ids, 'rule.event_ids'), idsField('证据 ID', rule.evidence_ids, 'rule.evidence_ids'),
    ] })) },
    { title: '日志分析 · 来源', entries: log.sources.map((source, index) => ({ title: `来源 ${index + 1}`, fields: [
      { label: '证据 ID', value: source.evidence_id }, { label: '来源引用', value: source.source_ref },
      ...countField('行号', source.line_number, 'source.line_number'), ...countField('记录号', source.record_number, 'source.record_number'),
      ...optionalField('SHA-256', source.sha256, 'source.sha256'),
    ] })) },
  ]
}

/** @param {string} value @returns {string} */
function filenamePart(value) {
  return value.normalize('NFKC').replace(/[^\p{L}\p{N}_-]+/gu, '_').replace(/^_+|_+$/g, '').slice(0, 64)
}

/**
 * Project only public report content; never traverse run execution/configuration,
 * finding.raw, evidence.metadata, uploaded artifacts, or retest snapshots.
 * Finding IDs are unique across sections: confirmed, candidate, then legacy.
 * No timestamps, locale conversions, sorting, network calls or input mutation.
 * @param {ExportReportInput} report
 * @param {ExportRunInput | null | undefined} run
 * @returns {ReportDocument}
 */
export function projectReport(report, run) {
  objectValue(report, 'report')
  const runId = textValue(report.run_id, 'report.run_id')
  if (!runId.trim()) throw new TypeError('report.run_id 不能为空；请刷新报告后重试')
  const status = textValue(report.status, 'report.status')
  if (!['pending', 'running', 'waiting_approval', 'completed', 'partial', 'denied', 'failed'].includes(status)) throw new TypeError('report.status 无效；请刷新报告后重试')
  if (run !== null && run !== undefined) {
    objectValue(run, 'run')
    if (textValue(run.run_id, 'run.run_id') !== runId) throw new RangeError('报告与当前任务 ID 不一致；请重新选择任务后导出')
  }
  const name = optionalField('任务名称', run?.name, 'run.name')
  const confirmed = arrayValue(report.confirmed_findings, 'report.confirmed_findings').map((item, index) => findingValue(item, `report.confirmed_findings[${index}]`))
  const candidates = arrayValue(report.candidate_findings, 'report.candidate_findings').map((item, index) => findingValue(item, `report.candidate_findings[${index}]`))
  const legacy = arrayValue(report.findings, 'report.findings').map((item, index) => findingValue(item, `report.findings[${index}]`))
  const uniqueConfirmed = confirmed.filter((item, index) => confirmed.findIndex(other => other.finding_id === item.finding_id) === index)
  const uniqueCandidates = candidates.filter((item, index) => !uniqueConfirmed.some(other => other.finding_id === item.finding_id)
    && candidates.findIndex(other => other.finding_id === item.finding_id) === index)
  const remaining = legacy.filter((item, index) => !uniqueConfirmed.some(other => other.finding_id === item.finding_id)
    && !uniqueCandidates.some(other => other.finding_id === item.finding_id) && legacy.findIndex(other => other.finding_id === item.finding_id) === index)
  return {
    title: 'SecMind 安全分析报告',
    filenameStem: ['secmind-report', name.length ? filenamePart(name[0].value) : '', filenamePart(runId) || 'run'].filter(Boolean).join('-'),
    sections: [
      { title: '任务信息', entries: [{ title: '报告信息', fields: [
        ...name, { label: '任务 ID', value: runId }, { label: '报告状态', value: status },
        ...optionalField('生成时间', report.generated_at, 'report.generated_at'),
        ...optionalField('任务目标', run?.objective, 'run.objective'),
        ...(run?.target_scope === undefined ? [] : [idsField('授权范围', run.target_scope, 'run.target_scope')]),
      ] }] },
      { title: '执行摘要', entries: [{ title: '摘要', fields: [field('内容', report.executive_summary, 'report.executive_summary')] }] },
      ...textSection('已验证输出', report.verified_outputs, 'report.verified_outputs'),
      { title: '已确认发现', entries: uniqueConfirmed.map(findingEntry) },
      { title: '待验证候选', entries: uniqueCandidates.map(findingEntry) },
      ...(remaining.length ? [{ title: '其他发现（原报告未分区）', entries: remaining.map(findingEntry) }] : []),
      { title: '证据索引', entries: arrayValue(report.evidence, 'report.evidence').map(evidenceEntry) },
      ...logSections(report.log_analysis),
      ...textSection('已排除方向', report.ruled_out_directions, 'report.ruled_out_directions'),
      ...textSection('证据不足', report.insufficient_evidence, 'report.insufficient_evidence'),
      ...textSection('Worker 报告', report.worker_reports, 'report.worker_reports'),
      ...textSection('执行限制', report.limitations, 'report.limitations'),
      ...(report.retests === undefined ? [] : [{ title: '独立复核记录', entries: arrayValue(report.retests, 'report.retests').map(retestEntry) }]),
    ],
  }
}

/**
 * Literal fenced text prevents Markdown HTML, image and link interpretation.
 * A fence longer than every embedded backtick run cannot be closed by input.
 * @param {string} value
 * @returns {string}
 */
function markdownLiteral(value) {
  const longest = (value.match(/`+/g) || []).reduce((length, match) => Math.max(length, match.length), 0)
  const fence = '`'.repeat(Math.max(3, longest + 1))
  return `${fence}text\n${value}\n${fence}`
}

/** @param {ReportDocument} document @returns {string} */
export function renderReportMarkdown(document) {
  return [`# ${document.title}`, ...document.sections.map(section => [
    `## ${section.title}`, section.entries.length ? section.entries.map(entry => [
      `### ${entry.title}`, ...entry.fields.map(item => `**${item.label}**\n\n${markdownLiteral(item.value)}`),
    ].join('\n\n')).join('\n\n') : '无记录。',
  ].join('\n\n'))].join('\n\n') + '\n'
}

/** @param {string} value @returns {string} */
function escapeHtml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

/** @param {ReportDocument} document @returns {string} */
export function renderReportHtml(document) {
  const sections = document.sections.map(section => `<section><h2>${escapeHtml(section.title)}</h2>${section.entries.length
    ? section.entries.map(entry => `<article><h3>${escapeHtml(entry.title)}</h3><dl>${entry.fields.map(item => `<dt>${escapeHtml(item.label)}</dt><dd><pre>${escapeHtml(item.value)}</pre></dd>`).join('')}</dl></article>`).join('')
    : '<p>无记录。</p>'}</section>`).join('\n')
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${escapeHtml(document.title)}</title>
<style>
:root{color-scheme:light;font-family:system-ui,"Microsoft YaHei",sans-serif;color:#182b38;background:#edf2f5}body{max-width:960px;margin:36px auto;padding:32px;background:white;line-height:1.65}h1{font-size:28px;border-bottom:3px solid #226779;padding-bottom:16px}h2{font-size:21px;color:#185667;border-bottom:1px solid #ccd9df;padding-bottom:8px;margin-top:32px}h3{font-size:16px;margin:0 0 12px}article{border:1px solid #d8e1e6;border-radius:8px;padding:18px;margin:16px 0}dl{margin:0}dt{font-weight:650;color:#3f5968;margin-top:12px}dd{margin:4px 0 0}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;margin:0}footer{margin-top:32px;color:#526875;font-size:12px}h1,h2,h3{break-after:avoid}@page{size:A4;margin:18mm}@media print{:root{background:white}body{max-width:none;margin:0;padding:0;font-size:10pt}h1{font-size:20pt}h2{font-size:15pt}article{border-radius:0}pre{orphans:3;widows:3}}
</style></head><body><h1>${escapeHtml(document.title)}</h1>${sections}<footer>仅导出当前结构化报告；不包含上传原件、证据附件正文或私密运行配置。请按数据授权范围分享。</footer></body></html>\n`
}

/** @param {ExportReportInput} report @param {ExportRunInput | null | undefined} run @returns {ReportDownloads} */
export function createReportDownloads(report, run) {
  const document = projectReport(report, run)
  return {
    markdown: { filename: `${document.filenameStem}.md`, mimeType: 'text/markdown;charset=utf-8', content: renderReportMarkdown(document) },
    html: { filename: `${document.filenameStem}.html`, mimeType: 'text/html;charset=utf-8', content: renderReportHtml(document) },
  }
}

/** @param {ReportDownload} file @returns {void} */
export function downloadReport(file) {
  const anchor = document.createElement('a')
  const url = URL.createObjectURL(new Blob([file.content], { type: file.mimeType }))
  try {
    anchor.href = url
    anchor.download = file.filename
    document.body.appendChild(anchor)
    anchor.click()
  } finally {
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}
