import { routeFor, externalSuccess } from './runStatus.js'

export function projectModuleFlow(run, events = []) {
  const latest = (type) => [...events].reverse().find((event) => event.event_type === type)?.payload
  if (routeFor(run) === 'penetration' && run?.routing?.execution_backend !== 'mcp') {
    const external = { ...latest('penetration.status'), ...run?.external_execution }
    const observations = run?.observations || []
    const observation = [...observations].reverse().find((item) => item.data?.external_intents)?.data || {}
    const intents = observation.external_intents || []
    return [
      { label: 'Origin', detail: '项目已提交', complete: Boolean(external.project_id) },
      { label: 'Intent', detail: '真实意图记录', complete: Number(external.intent_count || intents.length) > 0 },
      { label: 'Worker', detail: '真实执行器分配', complete: intents.some((item) => Boolean(item.worker)) || Number(external.worker_count) > 0 },
      { label: 'Fact', detail: '执行产出事实', complete: (observation.external_facts || []).some((item) => !['origin', 'goal'].includes(item.id)) || Number(external.fact_count) > 2 },
      { label: 'Goal', detail: '终态与目标验证', complete: externalSuccess.has(external.status) && external.objective_reached === true },
    ]
  }
  const lifecycle = [...events].reverse().find((event) => ['agent.started', 'agent.completed', 'agent.failed'].includes(event.event_type))
  const activeNode = run?.status === 'running' && lifecycle?.event_type === 'agent.started' ? lifecycle.payload?.node : null
  const definitions = [
    ['输入材料', '安全导入', 'input.ingested', 'ingest'],
    ['题型识别', '实际路由', 'scenario.classified', 'classify'],
    ['任务规划', '有界计划', 'plan.created', 'plan'],
    ['工具分析', '工具执行', 'tool.completed', 'execute'],
    ['证据归一化', '发现与证据', 'analysis.completed', 'analyze'],
    ['结论验证', '证据检查', 'verification.completed', 'verify'],
    ['报告生成', '统一报告', 'report.generated', 'report'],
  ]
  return definitions.map(([label, detail, type, node]) => {
    const payload = latest(type)
    let complete = payload !== undefined
    if (type === 'input.ingested') complete = complete && !payload.error
    if (type === 'tool.completed') complete = payload?.status === 'success'
    if (type === 'verification.completed') complete = complete && !payload.error && payload.route !== 'reflect'
    return { label, detail, complete, active: activeNode === node }
  })
}
