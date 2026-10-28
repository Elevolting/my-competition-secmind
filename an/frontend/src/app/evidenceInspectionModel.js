import { parseLogAnalysis } from './logAnalysisModel.js'

/** @typedef {import('./logAnalysisModel.js').JsonValue} JsonValue */
/** @typedef {import('./logAnalysisModel.js').LogEvent} LogEvent */
/** @typedef {import('./logAnalysisModel.js').LogSource} LogSource */
/** @typedef {import('./logAnalysisModel.js').LogAnalysisReport} LogAnalysisReport */
/** @typedef {{ evidence_id: string, source: string, summary: string, artifact_ref: string | null, sha256: string | null, metadata: { [key: string]: JsonValue } }} SavedEvidence */
/** @typedef {{ evidence: SavedEvidence[], logAnalysis: LogAnalysisReport | null }} EvidenceReport */

/** @param {JsonValue | undefined} value @param {string} path @returns {{ [key: string]: JsonValue }} */
function recordValue(value, path) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${path} 必须是对象`)
  return value
}

/** @param {JsonValue | undefined} value @param {string} path @returns {string} */
function textValue(value, path) {
  if (typeof value !== 'string') throw new TypeError(`${path} 必须是字符串`)
  return value
}

/** @param {JsonValue | undefined} value @param {string} path @returns {string | null} */
function optionalText(value, path) {
  return value === null ? null : textValue(value, path)
}

/** @param {JsonValue} value @param {string} path @param {number} depth @returns {void} */
function validateJson(value, path, depth) {
  if (depth > 30) throw new TypeError(`${path} 超过元数据深度上限 30`)
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number' && Number.isFinite(value)) return
  if (typeof value !== 'object') throw new TypeError(`${path} 必须是 JSON 值`)
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateJson(item, `${path}[${index}]`, depth + 1))
    return
  }
  Object.entries(value).forEach(([key, item]) => validateJson(item, `${path}.${key}`, depth + 1))
}

/** @param {JsonValue} value @param {number} index @returns {SavedEvidence} */
function parseEvidence(value, index) {
  const path = `report.evidence[${index}]`
  const row = recordValue(value, path)
  const metadata = recordValue(row.metadata, `${path}.metadata`)
  validateJson(metadata, `${path}.metadata`, 0)
  return {
    evidence_id: textValue(row.evidence_id, `${path}.evidence_id`),
    source: textValue(row.source, `${path}.source`), summary: textValue(row.summary, `${path}.summary`),
    artifact_ref: optionalText(row.artifact_ref, `${path}.artifact_ref`),
    sha256: optionalText(row.sha256, `${path}.sha256`), metadata,
  }
}

/** Validate saved data only; never resolve artifact paths or fetch additional content.
 * @param {JsonValue | undefined} value @returns {EvidenceReport}
 */
export function parseEvidenceReport(value) {
  const report = recordValue(value, 'report')
  if (!Array.isArray(report.evidence)) throw new TypeError('report.evidence 必须是数组')
  return { evidence: report.evidence.map(parseEvidence), logAnalysis: parseLogAnalysis(report.log_analysis) }
}

/** Exact IDs only; duplicates are an explicit ambiguity rather than a first-match guess.
 * @template T @param {T[]} rows @param {(row: T) => string} key @param {string} id @param {string} path @returns {T | null}
 */
export function resolveReference(rows, key, id, path) {
  const matches = rows.filter((row) => key(row) === id)
  if (matches.length > 1) throw new TypeError(`${path} 引用 ${id} 对应 ${matches.length} 条记录，无法唯一定位`)
  return matches[0] ?? null
}

/** Source identity excludes mutable content such as SHA-256; duplicate identities remain ambiguous.
 * @param {LogSource} source @returns {string}
 */
export function sourceReferenceKey(source) {
  return JSON.stringify([source.evidence_id, source.source_ref, source.line_number, source.record_number])
}

/** Match the actual source location, not merely a filename shared by unrelated records.
 * @param {LogEvent} event @param {LogSource[]} sources @returns {LogSource[]}
 */
export function eventSources(event, sources) {
  const locator = event.source_locator
  if (locator === null) return []
  return sources.filter((source) => source.source_ref === locator.source_ref
    && (locator.line_number === null || source.line_number === locator.line_number)
    && (locator.record_number === null || source.record_number === locator.record_number))
}

/** Bound rendered text without treating omission as saved evidence.
 * @param {string} value @param {number} limit @returns {string}
 */
export function boundedText(value, limit) {
  return value.length > limit ? `${value.slice(0, limit)}\n…（展示已截断，原记录未修改）` : value
}

/** A bounded JSON preview; omission markers describe display limits, never missing data.
 * @param {JsonValue} value @returns {string}
 */
export function boundedJson(value) {
  let visited = 0
  /** @param {JsonValue} item @param {number} depth @returns {JsonValue} */
  function preview(item, depth) {
    visited += 1
    if (visited > 200) return '…（展示节点上限 200）'
    if (typeof item === 'string') return boundedText(item, 4000)
    if (item === null || typeof item !== 'object') return item
    if (depth >= 5) return '…（展示深度上限 5）'
    if (Array.isArray(item)) {
      const values = item.slice(0, 20).map((entry) => preview(entry, depth + 1))
      return item.length > 20 ? [...values, `…（另有 ${item.length - 20} 项）`] : values
    }
    const entries = Object.entries(item)
    const values = Object.fromEntries(entries.slice(0, 20).map(([key, entry]) => [key, preview(entry, depth + 1)]))
    return entries.length > 20 ? { ...values, '…（展示省略）': `另有 ${entries.length - 20} 个字段` } : values
  }
  return boundedText(JSON.stringify(preview(value, 0), null, 2), 20000)
}
