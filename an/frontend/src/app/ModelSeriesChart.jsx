import React, { useEffect, useId, useRef, useState } from 'react'
import { Empty, Segmented, Select } from 'antd'
import { RobotOutlined } from '@ant-design/icons'

const ranges = { day: ['hourly', 24, '最近 24 小时'], week: ['daily', 7, '最近 7 天'], month: ['daily', 30, '最近 30 天'], year: ['monthly', 12, '最近 12 个月'] }
const segments = [
  ['cache_read_tokens', '输入 · 已记录缓存命中', '#a6ddf5'],
  ['other_input_tokens', '输入 · 其余输入', '#52aef5'],
  ['completion_tokens', '输出', '#2478ef'],
  ['unclassified_tokens', '未分类 Token', '#9b89ca'],
]
const number = value => Number(value || 0).toLocaleString('zh-CN')
const short = value => value >= 1e6 ? `${(value / 1e6).toFixed(1)}M` : value >= 1e3 ? `${(value / 1e3).toFixed(1)}K` : String(value)
const sum = (points, key) => points.reduce((total, point) => total + Number(point[key] || 0), 0)
const known = points => points.some(point => point.usage_receipt_count > 0) || points.every(point => !point.calls)
const displayTokens = points => known(points) ? number(sum(points, 'tokens')) : '—'

export function ModelSeriesChart({ usage }) {
  // Start on the longest available trend window. The separate cumulative
  // total above remains authoritative if history exceeds twelve months.
  const [range, setRange] = useState('year')
  const [model, setModel] = useState('all')
  const [period, count, label] = ranges[range]
  const available = usage.models || []
  const selected = model === 'all' || available.some(item => item.model === model) ? model : 'all'
  const slice = series => (series?.[period] || []).slice(-count)
  const points = slice(selected === 'all' ? usage.series : usage.model_series?.[selected])
  const models = selected === 'all' ? available : available.filter(item => item.model === selected)
  return <div className="usage-dashboard">
    <div className="usage-dashboard-toolbar">
      <Select aria-label="用量模型筛选" value={selected} onChange={setModel} options={[{ value: 'all', label: '全部模型' }, ...available.map(item => ({ value: item.model, label: item.model }))]} />
      <Segmented aria-label="用量时间范围" value={range} onChange={setRange} options={Object.entries(ranges).map(([value, item]) => ({ value, label: item[2] }))} />
    </div>
    <div className="usage-filter-caption">{selected === 'all' ? '全部模型 · 以下按实际调用模型分组' : `当前模型 · ${selected}`}<span>{label} · 数据来自本地 Provider 回执</span></div>
    <section className="usage-chart-card is-total">
      <header><div><span>所选时间范围 Token</span><strong data-testid="range-tokens">{displayTokens(points)}</strong></div><small>{label} · Asia/Shanghai</small></header>
      <UsageChart points={points} kind="total" period={period} label="Token 消耗趋势" />
      <footer><span><i className="legend-dot is-orange" />已记录的 Token</span><span>{number(sum(points, 'calls'))} 次请求 / CLI 执行 · {number(sum(points, 'usage_receipt_count'))} 份用量回执</span></footer>
    </section>
    {models.map(item => {
      const modelPoints = slice(usage.model_series?.[item.model])
      return <section className="model-usage-section" key={item.model}>
        <header className="model-usage-title"><h3><RobotOutlined />{item.model}</h3><span>{selected === 'all' ? '历史模型分组' : '当前筛选模型'} · {label}</span></header>
        <div className="model-chart-pair">
          <section className="usage-chart-card"><header><div><span>请求 / CLI 执行次数</span><strong>{number(sum(modelPoints, 'calls'))}</strong></div><small>包含失败调用</small></header><UsageChart points={modelPoints} kind="calls" period={period} label={`${item.model} 请求与执行趋势`} /></section>
          <section className="usage-chart-card"><header><div><span>Tokens</span><strong>{displayTokens(modelPoints)}</strong></div><small>按回执构成</small></header><UsageChart points={modelPoints} kind="stack" period={period} label={`${item.model} Token 构成`} /><footer className="token-legend">{segments.filter(([key]) => key !== 'unclassified_tokens' || sum(modelPoints, key)).map(([key, text, color]) => <span key={key}><i style={{ background: color }} />{text}</span>)}</footer></section>
        </div>
      </section>
    })}
    {!models.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无实际模型调用" />}
    <p className="usage-chart-note">缓存是输入 Token 的一部分。历史未提供缓存细分的输入归入“其余输入”；没有回执的调用不会估算 Token。费用尚未接入供应商账单。</p>
  </div>
}

export function UsageChart({ points, kind, period, label, reference = 0 }) {
  const [hover, setHover] = useState(null)
  const container = useRef(null)
  const [width, setWidth] = useState(800)
  useEffect(() => {
    if (!container.current) return
    const observer = new ResizeObserver(entries => setWidth(Math.max(280, Math.round(entries[0].contentRect.width))))
    observer.observe(container.current)
    return () => observer.disconnect()
  }, [points.length])
  const uid = useId().replaceAll(':', '')
  const height = kind === 'total' ? 280 : 240, left = width < 400 ? 44 : 60, right = 12, top = reference > 0 ? 32 : 18, bottom = 34
  const plotWidth = width - left - right, plotHeight = height - top - bottom
  const values = points.map(point => Number(point[kind === 'calls' ? 'calls' : 'tokens'] || 0))
  const peak = Math.max(...values, reference, 1)
  const scale = 10 ** Math.floor(Math.log10(peak))
  const max = Math.ceil(peak / scale) * scale
  const step = plotWidth / Math.max(points.length, 1)
  const x = index => left + step * (index + .5)
  const y = value => top + plotHeight * (1 - value / max)
  const base = height - bottom
  const line = values.map((value, index) => `${index ? 'L' : 'M'}${x(index)},${y(value)}`).join(' ')
  const labels = new Set(kind === 'budget' && points.length <= 12 && width > 650 ? points.map((_, index) => index) : [0, Math.floor((points.length - 1) / 3), Math.floor((points.length - 1) * 2 / 3), points.length - 1])
  const labelDate = bucket => period === 'hourly' ? bucket.slice(11, 16) : period === 'monthly' ? bucket : bucket.slice(5).replace('-', '/')
  const active = hover == null ? null : points[hover]
  if (!points.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="此范围暂无趋势数据" />
  return <div ref={container} className={`usage-svg-chart is-${kind}`} onMouseLeave={() => setHover(null)}>
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <defs><linearGradient id={uid} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#318efa" stopOpacity=".55" /><stop offset="100%" stopColor="#318efa" stopOpacity=".04" /></linearGradient><linearGradient id={`${uid}-bar`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#70b5ff" /><stop offset="100%" stopColor="#347eea" /></linearGradient></defs>
      {[0, .5, 1].map(fraction => <g key={fraction}><line className="chart-gridline" x1={left} x2={width - right} y1={y(max * fraction)} y2={y(max * fraction)} /><text className="chart-axis" x={left - 12} y={y(max * fraction) + 4} textAnchor="end">{short(max * fraction)}</text></g>)}
      {kind === 'calls' && <><path d={`${line} L${x(points.length - 1)},${base} L${x(0)},${base} Z`} fill={`url(#${uid})`} /><path d={line} fill="none" stroke="#318efa" strokeWidth="2.5" strokeLinejoin="round" /></>}
      {points.map((point, index) => <g key={point.bucket}>
        {kind === 'budget' && <rect className="budget-chart-bar" x={x(index) - Math.min(step * .48, 40) / 2} y={y(values[index])} width={Math.min(step * .48, 40)} height={Math.max(0, base - y(values[index]))} rx="5" fill={hover === index ? '#2778e9' : `url(#${uid}-bar)`} />}
        {kind === 'total' && <rect x={x(index) - step * .32} y={y(values[index])} width={step * .64} height={Math.max(0, base - y(values[index]))} rx="3" fill={hover === index ? '#ffab69' : '#ff791a'} />}
        {kind === 'stack' && segments.map(([key, , color], segmentIndex) => {
          const previous = segments.slice(0, segmentIndex).reduce((value, [field]) => value + Number(point[field] || 0), 0)
          const amount = Number(point[key] || 0)
          return <rect key={key} x={x(index) - step * .32} y={y(previous + amount)} width={step * .64} height={Math.max(0, amount / max * plotHeight)} fill={color} />
        })}
        {labels.has(index) && <text className="chart-axis" x={x(index)} y={height - 8} textAnchor="middle">{labelDate(point.bucket)}</text>}
        <rect className="chart-hit" x={left + step * index} y={top} width={step} height={plotHeight} fill="transparent" tabIndex="0" role="button" aria-label={`${label} ${point.bucket}: ${number(values[index])}`} onMouseEnter={() => setHover(index)} onFocus={() => setHover(index)} onBlur={() => setHover(null)} onClick={() => setHover(index)} onKeyDown={event => { if (event.key === 'Escape') setHover(null); if (event.key === 'ArrowRight') { event.preventDefault(); event.currentTarget.parentNode.nextElementSibling?.querySelector('.chart-hit')?.focus() } if (event.key === 'ArrowLeft') { event.preventDefault(); event.currentTarget.parentNode.previousElementSibling?.querySelector('.chart-hit')?.focus() } }} />
      </g>)}
      {reference > 0 && <g className="budget-reference" pointerEvents="none"><line x1={left} x2={width-right} y1={y(reference)} y2={y(reference)} stroke="#d99536" strokeDasharray="6 5" /><text x={width-right} y={y(reference)-8} textAnchor="end" fill="#b9802e" fontSize="11">预算 {short(reference)}</text></g>}
      {active && <line className="chart-cursor" x1={x(hover)} x2={x(hover)} y1={top} y2={base} pointerEvents="none" />}
    </svg>
      {active && <div className="usage-chart-tooltip" role="tooltip" style={{ left: `${Math.min(64, Math.max(2, x(hover) / width * 100 - 14))}%` }}><b>{active.bucket.replace('T', ' ').replace('+08:00', '')}</b>{kind === 'calls' ? <p>请求 / CLI 执行 <strong>{number(active.calls)}</strong></p> : <><p>已知 Token <strong>{active.calls && !active.usage_receipt_count ? '—' : number(active.tokens)}</strong></p>{kind === 'stack' && segments.filter(([key]) => key !== 'unclassified_tokens' || active[key]).map(([key, text, color]) => <p key={key}><span><i style={{ background: color }} />{text}</span><strong>{active.usage_receipt_count ? number(active[key]) : '—'}</strong></p>)}</>}<small>{active.calls} 次请求 / CLI 执行 · {active.usage_receipt_count} 份用量回执</small></div>}
  </div>
}
