// Pure run-state projections shared by the dashboard and tests.  Keep the
// external Security Runtime state authoritative for penetration runs: a submitted or
// running project is never a completed task.
export const externalSuccess = new Set(['completed', 'complete', 'succeeded', 'success'])
export const externalFailure = new Set(['failed', 'denied', 'cancelled', 'canceled', 'error'])
export const externalUnavailable = new Set(['timeout', 'unavailable', 'poll_error'])

export function externalStatus(run) {
  return String(run?.external_execution?.status || '').trim().toLowerCase()
}

export function routeFor(run) {
  const value = String(run?.module_route || run?.scenario || '').trim().toLowerCase()
  const scenario = String(run?.scenario || '').trim().toLowerCase()
  if (value === 'audit' && ['reverse_triage', 'penetration_test', 'reverse', 'penetration'].includes(scenario)) return ({ reverse_triage: 'reverse', penetration_test: 'penetration' })[scenario] || scenario
  return ({ audit: 'code_audit', penetration_test: 'penetration', reverse_triage: 'reverse' })[value] || value || 'unknown'
}

export function isSuccessfulRun(run) {
  if (String(run?.status || '').toLowerCase() !== 'completed') return false
  if (routeFor(run) !== 'penetration' || run?.routing?.execution_backend === 'mcp') return true
  return externalSuccess.has(externalStatus(run)) && run?.external_execution?.objective_reached === true
}

/** Return one mutually-exclusive bucket for overview statistics. */
export function classifyRunStatus(run) {
  const status = String(run?.status || '').toLowerCase()
  const external = externalStatus(run)
  if (isSuccessfulRun(run)) return 'completed'
  if (externalUnavailable.has(external)) return external
  if (externalFailure.has(external)) return 'failed'
  if (status === 'partial') return 'partial'
  if (status === 'failed' || status === 'denied') return 'failed'
  if (status === 'waiting_approval') return 'waiting_approval'
  return 'running'
}

export function summarizeRunStatuses(runs = []) {
  const summary = { completed: 0, partial: 0, failed: 0, timeout: 0, unavailable: 0, waiting_approval: 0, running: 0 }
  for (const run of runs) {
    const bucket = classifyRunStatus(run)
    if (bucket === 'poll_error') summary.unavailable += 1
    else if (Object.prototype.hasOwnProperty.call(summary, bucket)) summary[bucket] += 1
    else summary.running += 1
  }
  return summary
}

export function isAttentionRun(run) {
  return ['partial', 'failed', 'timeout', 'unavailable', 'waiting_approval'].includes(classifyRunStatus(run))
}

export function isActiveRun(run) {
  return classifyRunStatus(run) === 'running'
}
