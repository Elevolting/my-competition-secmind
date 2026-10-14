const findingTranslations = {
  B105: {
    title: '检测到硬编码密钥',
    description: '源码中可能包含硬编码的密码、令牌或其他敏感信息。',
    remediation: '将密钥迁移至安全的密钥管理服务，并轮换已经暴露的密钥。',
  },
  B301: {
    title: '使用不安全的反序列化方法',
    description: '不安全的反序列化可能允许攻击者构造恶意对象并触发非预期行为。',
    remediation: '改用经过结构校验的 JSON 等安全数据格式。',
  },
  B602: {
    title: '使用 shell=True 执行子进程',
    description: '通过 Shell 解释命令可能引入命令注入风险。',
    remediation: '禁用 shell=True，并向子进程传递固定参数列表。',
  },
  B608: {
    title: '通过字符串拼接构造 SQL',
    description: '动态拼接 SQL 可能引入 SQL 注入风险。',
    remediation: '使用参数化查询或安全的 ORM 查询接口。',
  },
  'AUDIT-SHELL-RANDOM-NAME': {
    title: '使用随机文件名保护密钥',
    description: '将密钥重命名为随机文件名并不构成访问控制，仍可能导致敏感内容泄露。',
    remediation: '将密钥存放在应用文件系统之外，并在访问点实施严格的身份验证和授权。',
  },
  'AUDIT-SECRET-FLAG': {
    title: '源码材料中存有敏感挑战密钥',
    description: '项目文件以明文保存了类似 flag 的敏感内容；证据中已主动隐藏匹配到的具体值。',
    remediation: '应在运行时注入密钥，并从源码压缩包和构建上下文中排除真实密钥。',
  },
  'AUDIT-LEGACY-SPRING': {
    title: '使用已停止安全维护的 Spring Boot 依赖',
    description: '项目使用 Spring Boot 1.x 父依赖，该版本已不再获得安全更新。',
    remediation: '升级至仍受支持的 Spring Boot 版本，并在部署前执行依赖漏洞分析。',
  },
  'AUDIT-LEGACY-VELOCITY': {
    title: '使用过时的 Apache Velocity 依赖',
    description: 'Apache Velocity 1.7 已经过时；当模板包含不可信数据时，其安全风险尤其突出。',
    remediation: '移除对不可信模板的运行时解析，并迁移至仍受支持的模板引擎版本。',
  },
  'AUDIT-JAVA-SSTI': {
    title: '用户可控输入进入服务端模板解析器',
    description: '请求参数与运行时模板解析出现在同一源码文件中，形成服务端模板注入攻击路径。',
    remediation: '禁止编译包含请求数据的模板；不可信输入只能作为经过转义的模板上下文变量传递。',
  },
}

const exactTranslations = {
  'Scenario selected from the operator objective and immutable input inventory.': '已根据用户任务目标和不可变输入清单识别任务场景。',
  'No external knowledge was required for the deterministic Bandit baseline.': '当前只读静态审计不需要外部知识上下文。',
  'Read-only operation is allowed inside the controlled workspace.': '允许在受控工作区内执行只读操作。',
  'All normalized findings reference captured tool evidence.': '所有规范化安全发现均已关联到实际采集的工具证据。',
  'Verified completed runs are eligible for episodic-memory curation.': '已完成且通过验证的任务可进入情景记忆候选。',
  'Only verified completed runs may enter long-term memory.': '只有已完成且通过验证的任务才能进入长期记忆。',
  'The selected scenario is not enabled in the MVP tool chain.': '当前工具链尚不支持所选任务场景。',
  'No input artifacts were supplied; the workspace may contain no analyzable code.': '未提供输入材料，工作区中可能没有可分析的代码。',
  'The task ended without a successful security-tool observation.': '任务结束，但没有获得成功的安全工具观测结果。',
}

export const severityLabels = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', UNKNOWN: '未知' }

export function localizePublicText(value) {
  if (value == null) return ''
  const text = String(value)
  if (exactTranslations[text]) return exactTranslations[text]
  let match = text.match(/^Code audit completed with (\d+) finding\(s\), supported by (\d+) evidence record\(s\)\.$/)
  if (match) return `代码审计完成，共发现 ${match[1]} 个安全问题，并由 ${match[2]} 条证据记录支持。`
  match = text.match(/^Bandit completed with (\d+) finding\(s\)\.$/)
  if (match) return `Bandit 扫描完成，共发现 ${match[1]} 个安全问题。`
  match = text.match(/^Workspace audit read (\d+)\/(\d+) file\(s\) and produced (\d+) finding\(s\)\.$/)
  if (match) return `工作区审计实际读取 ${match[1]}/${match[2]} 个文件，共发现 ${match[3]} 个安全问题。`
  if (/^Single bounded audit step/i.test(text)) return '已生成单步受控审计计划，将读取上传文件并检查漏洞及敏感信息暴露。'
  if (/^Static, read-only analysis/i.test(text)) return '采用静态只读分析，以确保执行过程安全且可复现。'
  return text
}

export function localizeFinding(finding) {
  const translated = findingTranslations[finding.rule_id]
  return translated ? { ...finding, ...translated } : {
    ...finding,
    title: localizePublicText(finding.title),
    description: localizePublicText(finding.description),
    remediation: localizePublicText(finding.remediation),
  }
}

export function localizeModelOutput(content) {
  if (!content) return '模型正在生成公开输出…'
  try {
    const parsed = JSON.parse(content)
    if (Array.isArray(parsed.steps)) {
      const tools = [...new Set(parsed.steps.flatMap((step) => step.tool_candidates || []))]
      return `模型生成了 ${parsed.steps.length} 个候选执行步骤。候选工具：${tools.join('、') || '无'}。系统会继续执行工具白名单、参数范围和证据要求校验。`
    }
  } catch {
  }
  return localizePublicText(content)
}
