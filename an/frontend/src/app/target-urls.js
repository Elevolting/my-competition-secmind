// Only treat punctuation as a separator when another address follows it, so
// commas, semicolons and Chinese text inside URL paths/queries stay intact.
const addressStart = String.raw`(?:https?:\/\/|(?:\[[0-9a-f:]+\]|localhost|(?:[\p{L}\d-]+\.)+[\p{L}\d-]+)(?=[:/\s,，;；、]|$))`
const addressSeparator = new RegExp(String.raw`\s+|[,，;；、和]\s*(?=${addressStart})`, 'iu')

export function parseTargetUrls(value = '') {
  const entries = value.trim().split(addressSeparator).filter(Boolean)
  const urls = entries.map((entry, index) => {
    const invalid = (detail) => new Error(`第 ${index + 1} 个靶场网址无效：${detail}`)
    const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(entry)
    const isHostPort = /^[^/:?#]+:\d+(?:[/?#]|$)/.test(entry)
    if (hasScheme && !isHostPort && !/^https?:\/\//i.test(entry)) {
      throw invalid('仅支持 http 或 https 地址')
    }
    const candidate = /^https?:\/\//i.test(entry) ? entry : `http://${entry}`
    let parsed
    try {
      parsed = new URL(candidate)
    } catch {
      throw invalid('请检查主机和端口，例如 http://10.0.0.1:8080；多个地址请换行分隔')
    }
    if (!parsed.hostname || parsed.username || parsed.password || /[\\\u0000-\u001f]/.test(entry) || /^\//.test(entry)) {
      throw invalid('请输入不含账号密码的主机地址，例如 http://10.0.0.1:8080')
    }
    if (/https?:\/\//i.test(parsed.pathname) || /%2f%2f/i.test(parsed.pathname) && /https?%3a/i.test(parsed.pathname)) {
      throw invalid('路径中包含另一个网址，请分别填写目标地址')
    }
    return parsed.href
  })
  return [...new Set(urls)]
}

export function targetScopeFor(values, targetUrls = []) {
  return [...new Set([values.targetScope?.trim(), ...targetUrls].filter(Boolean))]
}
