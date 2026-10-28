import { eventLabels } from './runtimeModel.js'

/** @typedef {'planning' | 'tools' | 'approval' | 'verification' | 'report'} ReplayPhase */
/** @typedef {{ event_type: string }} ReplayEvent */
/** @typedef {{ id: ReplayPhase, label: string, cursor: number | null }} PhaseTarget */

/** @type {ReadonlyArray<{ id: ReplayPhase, label: string }>} */
const phases = [
  { id: 'planning', label: '规划' },
  { id: 'tools', label: '工具' },
  { id: 'approval', label: '审批' },
  { id: 'verification', label: '验证' },
  { id: 'report', label: '报告' },
]

/** @param {string} type @returns {ReplayPhase | null} */
export function replayPhaseFor(type) {
  if (type.startsWith('approval.') || type.startsWith('guardrail.') || type.startsWith('mcp.approval.')
    || ['blackboard.denied', 'blackboard.interrupted'].includes(type)) return 'approval'
  if (type.startsWith('tool.') || type.startsWith('mcp.call.') || type === 'observation.recorded') return 'tools'
  if (type === 'verification.completed') return 'verification'
  if (type.startsWith('report.') || type === 'memory.candidate') return 'report'
  if (type.startsWith('plan.') || type.startsWith('exploration.') || type.startsWith('penetration.')
    || ['knowledge.planner_consumed', 'step.selected', 'reflection.completed',
      'blackboard.entered', 'blackboard.intent.scheduled'].includes(type)) return 'planning'
  return null
}

/** @param {number} cursor @param {number} eventCount @returns {number} */
export function boundReplayCursor(cursor, eventCount) {
  if (!Number.isFinite(cursor) || !Number.isInteger(eventCount) || eventCount < 0) {
    throw new RangeError(`Invalid replay position: cursor=${cursor}, eventCount=${eventCount}`)
  }
  return Math.min(eventCount, Math.max(0, Math.trunc(cursor)))
}

/**
 * Targets are event indexes plus one, never ledger sequence numbers. The first
 * actual event in each phase is its jump target; no history is synthesized.
 * @param {ReadonlyArray<ReplayEvent>} events
 * @returns {{ meaningful: number[], phases: PhaseTarget[] }}
 */
export function buildReplayNavigation(events) {
  const meaningful = events.flatMap((event, index) => {
    if (typeof event?.event_type !== 'string' || !event.event_type) {
      throw new TypeError(`Replay event at index ${index} requires a nonempty event_type`)
    }
    // Model streaming lifecycle and token chunks are not navigation milestones.
    if (event.event_type.startsWith('llm.')) return []
    return Object.hasOwn(eventLabels, event.event_type) || replayPhaseFor(event.event_type) !== null ? [index + 1] : []
  })
  return {
    meaningful,
    phases: phases.map((phase) => {
      const index = events.findIndex((event) => replayPhaseFor(event.event_type) === phase.id)
      return { ...phase, cursor: index < 0 ? null : index + 1 }
    }),
  }
}
