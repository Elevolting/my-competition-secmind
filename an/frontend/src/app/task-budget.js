export function defaultTaskBudget(config, primaryType) {
  const defaults = config.defaults
  return {
    max_runtime_seconds: Math.max(config.limits.max_runtime_seconds.min,
      primaryType === 'penetration' ? defaults.penetration_max_runtime_seconds : defaults.max_runtime_seconds),
    max_tool_calls: defaults.max_tool_calls,
    max_model_calls: primaryType === 'penetration'
      ? (defaults.penetration_max_model_calls ?? defaults.max_model_calls) : defaults.max_model_calls,
  }
}

export function validTaskBudget(budget, limits) {
  return Boolean(budget && limits && Object.entries(limits).every(([key, range]) =>
    Number.isInteger(budget[key]) && budget[key] >= range.min && budget[key] <= range.max))
}

// Suggest the current exploration defaults for a retry of an old, small-budget
// task. The operator sees and can edit all values before creating the new run.
export function retryTaskBudget(run, config) {
  const defaults = defaultTaskBudget(config, run.module_route)
  const exhausted = run.budget?.runtime_seconds_used >= run.budget?.max_runtime_seconds
  return Object.fromEntries(Object.entries(defaults).map(([key, value]) => [key,
    Math.min(config.limits[key].max, Math.max(value,
      (run.budget?.[key] || value) * (key === 'max_runtime_seconds' && exhausted ? 2 : 1))),
  ]))
}
