import React, { useMemo } from 'react'
import { Alert, Drawer } from 'antd'
import { boundedJson, boundedText, parseEvidenceReport, resolveReference } from './evidenceInspectionModel.js'
import './EvidenceDrawer.css'

/** @typedef {import('./logAnalysisModel.js').JsonValue} JsonValue */
/** @typedef {import('./evidenceInspectionModel.js').SavedEvidence} SavedEvidence */

/** @param {{ fields: [string, React.ReactNode][] }} props @returns {React.ReactNode} */
export function EvidenceFields({ fields }) {
  return <dl className="evidence-inspection-fields">{fields.map(([label, value]) => <React.Fragment key={label}>
    <dt>{label}</dt><dd>{value}</dd>
  </React.Fragment>)}</dl>
}

/** @param {{ value: JsonValue }} props @returns {React.ReactNode} */
export function EvidenceRawDetails({ value }) {
  return <details className="evidence-inspection-raw" data-testid="evidence-raw-details">
    <summary>展开原始 JSON（有界预览）</summary>
    <pre>{boundedJson(value)}</pre>
  </details>
}

/** @param {{ source: import('./logAnalysisModel.js').LogSource, evidenceLink: React.ReactNode }} props @returns {React.ReactNode} */
export function EvidenceSourceFields({ source, evidenceLink }) {
  return <EvidenceFields fields={[
    ['来源引用', boundedText(source.source_ref, 4000)], ['行号', source.line_number ?? '未记录'],
    ['记录号', source.record_number ?? '未记录'], ['证据 ID', evidenceLink], ['SHA-256', source.sha256 === null ? '未记录' : boundedText(source.sha256, 4000)],
  ]} />
}

/** @param {{ evidence: SavedEvidence }} props @returns {React.ReactNode} */
function SavedEvidenceDetails({ evidence }) {
  const entries = Object.entries(evidence.metadata)
  return <>
    <EvidenceFields fields={[
      ['证据 ID', boundedText(evidence.evidence_id, 4000)], ['来源', boundedText(evidence.source, 4000)],
      ['摘要', boundedText(evidence.summary, 8000)],
      ['产物引用', evidence.artifact_ref === null ? '未记录' : boundedText(evidence.artifact_ref, 4000)],
      ['SHA-256', evidence.sha256 === null ? '未记录' : boundedText(evidence.sha256, 4000)],
    ]} />
    <section aria-label="已保存元数据" data-testid="evidence-metadata">
      <h4>元数据</h4>
      {entries.length ? <EvidenceFields fields={entries.slice(0, 20).map(([key, value]) => [key,
        typeof value === 'string' ? boundedText(value, 2000) : boundedText(boundedJson(value), 2000),
      ])} /> : <p>未记录元数据</p>}
      {entries.length > 20 && <p role="status">仅展示前 20 个字段，另有 {entries.length - 20} 个字段。</p>}
    </section>
    <EvidenceRawDetails value={evidence} />
  </>
}

/** Read-only inspection of the supplied report. Artifact references are plain text, never file links.
 * @param {{ open: boolean, evidenceId: string | null, report: JsonValue | undefined, onClose: () => void }} props
 * @returns {React.ReactNode}
 */
export function EvidenceDrawer({ open, evidenceId, report, onClose }) {
  const result = useMemo(() => {
    if (!open) return null
    try {
      if (typeof evidenceId !== 'string' || evidenceId.length === 0) throw new TypeError('evidenceId 必须是非空字符串')
      const data = parseEvidenceReport(report)
      return { evidence: resolveReference(data.evidence, (row) => row.evidence_id, evidenceId, 'report.evidence'),
        sources: data.logAnalysis === null ? [] : data.logAnalysis.sources.filter((source) => source.evidence_id === evidenceId), error: null }
    } catch (cause) {
      if (!(cause instanceof TypeError)) throw cause
      return { evidence: null, sources: [], error: cause.message }
    }
  }, [open, evidenceId, report])
  return <Drawer title="证据详情" open={open} onClose={onClose} size={720} destroyOnHidden
    className="evidence-inspection-drawer" data-testid="evidence-drawer">
    <div className="evidence-inspection" data-testid="evidence-drawer-content">
      {result?.error ? <Alert type="error" showIcon title="证据数据无效" description={result.error} data-testid="evidence-invalid" /> : result && <>
        {result.evidence ? <SavedEvidenceDetails evidence={result.evidence} /> : <Alert type="warning" showIcon
          title="未找到证据记录" description={`report.evidence 中不存在引用 ${evidenceId}；不能从来源行推断证据正文。`} data-testid="evidence-missing" />}
        <section aria-label="关联日志来源" data-testid="evidence-log-sources">
          <h4>关联日志来源 · {result.sources.length}</h4>
          {result.sources.length ? <>
            {result.sources.slice(0, 20).map((source, index) => <section className="evidence-inspection-source" key={index}>
              <EvidenceSourceFields source={source} evidenceLink={<code>{boundedText(source.evidence_id, 4000)}</code>} />
            </section>)}
            {result.sources.length > 20 && <p role="status">仅展示前 20 条来源，另有 {result.sources.length - 20} 条。</p>}
          </> : <p>报告未记录此证据的日志来源引用。</p>}
        </section>
      </>}
    </div>
  </Drawer>
}
