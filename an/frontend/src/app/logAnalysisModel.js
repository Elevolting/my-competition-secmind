/** @typedef {string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }} JsonValue */
/** @typedef {{ source_ref: string, line_number: number | null, record_number: number | null, byte_offset: number | null, byte_length: number | null }} LogSourceLocator */
/** @typedef {{ event_id: string, timestamp: string | null, event_type: string, severity: string | null, message: string, evidence_ids: string[], source_locator: LogSourceLocator | null }} LogEvent */
/** @typedef {{ ioc_type: string, value: string, event_id: string | null, evidence_ids: string[] }} LogIoc */
/** @typedef {{ rule_id: string, title: string, severity: string, event_ids: string[], evidence_ids: string[] }} LogRuleMatch */
/** @typedef {{ sources_processed: number | null, input_records: number | null, parsed_records: number | null, rejected_records: number | null, duplicates_removed: number | null }} LogStatistics */
/** @typedef {{ evidence_id: string, source_ref: string, line_number: number | null, record_number: number | null, sha256: string | null }} LogSource */
/** @typedef {{ events: LogEvent[], iocs: LogIoc[], rule_matches: LogRuleMatch[], statistics: LogStatistics, sources: LogSource[] }} LogAnalysisReport */

/** @param {JsonValue | undefined} value @param {string} path @returns {{ [key: string]: JsonValue }} */
function objectValue(value, path) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${path} 必须是对象`)
  return value
}

/** @param {JsonValue | undefined} value @param {string} path @returns {string} */
function stringValue(value, path) {
  if (typeof value !== 'string') throw new TypeError(`${path} 必须是字符串`)
  return value
}

/** @param {JsonValue | undefined} value @param {string} path @returns {string | null} */
function nullableString(value, path) {
  return value === null ? null : stringValue(value, path)
}

/** @param {JsonValue | undefined} value @param {string} path @returns {number | null} */
function nullableCount(value, path) {
  if (value === null) return null
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${path} 必须是非负整数或 null`)
  return value
}

/** @template T @param {JsonValue | undefined} value @param {string} path @param {(item: JsonValue, path: string) => T} read @returns {T[]} */
function arrayValue(value, path, read) {
  if (!Array.isArray(value)) throw new TypeError(`${path} 必须是数组`)
  return value.map((item, index) => read(item, `${path}[${index}]`))
}

/** @param {JsonValue | undefined} value @param {string} path @returns {LogSourceLocator | null} */
function sourceLocator(value, path) {
  if (value === null) return null
  const row = objectValue(value, path)
  return { source_ref: stringValue(row.source_ref, `${path}.source_ref`),
    line_number: nullableCount(row.line_number, `${path}.line_number`), record_number: nullableCount(row.record_number, `${path}.record_number`),
    byte_offset: nullableCount(row.byte_offset, `${path}.byte_offset`), byte_length: nullableCount(row.byte_length, `${path}.byte_length`) }
}

/** @param {JsonValue} value @param {string} path @returns {LogEvent} */
function eventValue(value, path) {
  const row = objectValue(value, path)
  return { event_id: stringValue(row.event_id, `${path}.event_id`), timestamp: nullableString(row.timestamp, `${path}.timestamp`),
    event_type: stringValue(row.event_type, `${path}.event_type`), severity: nullableString(row.severity, `${path}.severity`),
    message: stringValue(row.message, `${path}.message`), evidence_ids: arrayValue(row.evidence_ids, `${path}.evidence_ids`, stringValue),
    source_locator: sourceLocator(row.source_locator, `${path}.source_locator`) }
}

/** @param {JsonValue} value @param {string} path @returns {LogIoc} */
function iocValue(value, path) {
  const row = objectValue(value, path)
  return { ioc_type: stringValue(row.ioc_type, `${path}.ioc_type`), value: stringValue(row.value, `${path}.value`),
    event_id: nullableString(row.event_id, `${path}.event_id`), evidence_ids: arrayValue(row.evidence_ids, `${path}.evidence_ids`, stringValue) }
}

/** @param {JsonValue} value @param {string} path @returns {LogRuleMatch} */
function ruleValue(value, path) {
  const row = objectValue(value, path)
  return { rule_id: stringValue(row.rule_id, `${path}.rule_id`), title: stringValue(row.title, `${path}.title`),
    severity: stringValue(row.severity, `${path}.severity`), event_ids: arrayValue(row.event_ids, `${path}.event_ids`, stringValue),
    evidence_ids: arrayValue(row.evidence_ids, `${path}.evidence_ids`, stringValue) }
}

/** @param {JsonValue} value @param {string} path @returns {LogSource} */
function sourceValue(value, path) {
  const row = objectValue(value, path)
  return { evidence_id: stringValue(row.evidence_id, `${path}.evidence_id`), source_ref: stringValue(row.source_ref, `${path}.source_ref`),
    line_number: nullableCount(row.line_number, `${path}.line_number`), record_number: nullableCount(row.record_number, `${path}.record_number`),
    sha256: nullableString(row.sha256, `${path}.sha256`) }
}

/**
 * Validate the public report DTO, retaining only declared fields.
 * Missing top-level data is accepted only for legacy reports.
 * @param {JsonValue | undefined} value
 * @returns {LogAnalysisReport | null}
 */
export function parseLogAnalysis(value) {
  if (value === null || value === undefined) return null
  const path = 'report.log_analysis'
  const row = objectValue(value, path)
  const statistics = objectValue(row.statistics, `${path}.statistics`)
  return { events: arrayValue(row.events, `${path}.events`, eventValue), iocs: arrayValue(row.iocs, `${path}.iocs`, iocValue),
    rule_matches: arrayValue(row.rule_matches, `${path}.rule_matches`, ruleValue), sources: arrayValue(row.sources, `${path}.sources`, sourceValue),
    statistics: { sources_processed: nullableCount(statistics.sources_processed, `${path}.statistics.sources_processed`),
      input_records: nullableCount(statistics.input_records, `${path}.statistics.input_records`),
      parsed_records: nullableCount(statistics.parsed_records, `${path}.statistics.parsed_records`),
      rejected_records: nullableCount(statistics.rejected_records, `${path}.statistics.rejected_records`),
      duplicates_removed: nullableCount(statistics.duplicates_removed, `${path}.statistics.duplicates_removed`) } }
}
