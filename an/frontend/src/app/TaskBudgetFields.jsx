import React, { useId } from 'react'
import { InputNumber } from 'antd'

export function TaskBudgetFields({ budget, limits, onChange, disabled = false }) {
  const id = useId()
  const fields = [
    ['max_runtime_seconds', '总运行时间（分钟）', 60],
    ['max_tool_calls', '工具调用总量（次）', 1],
    ['max_model_calls', '模型请求总量（次）', 1],
  ]
  return <section aria-label="探索预算">
    <p><b>探索预算</b></p>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
      {fields.map(([key, label, divisor]) => <div key={key}>
        <label htmlFor={`${id}-${key}`}>{label}</label>
        <InputNumber id={`${id}-${key}`} style={{ width: '100%', marginTop: 6 }} disabled={disabled}
          min={Math.ceil(limits[key].min / divisor)} max={Math.floor(limits[key].max / divisor)} precision={0}
          value={budget[key] == null ? null : Math.ceil(budget[key] / divisor)}
          onChange={(value) => onChange({ ...budget, [key]: value == null ? null : value * divisor })} />
      </div>)}
    </div>
    <p><small>模型请求由规划、目标核验和 Worker 共用。单轮按时间收尾；任务总预算耗尽后停止，并保留已有结果。网络操作仍按所选授权策略执行。</small></p>
  </section>
}
