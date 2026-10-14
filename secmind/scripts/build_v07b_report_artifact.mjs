import fs from "node:fs";
import path from "node:path";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function requireArg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) {
    throw new Error(`missing ${name}`);
  }
  return process.argv[index + 1];
}

const input = requireArg("--input");
const diagnosticPath = requireArg("--diagnostic");
const output = requireArg("--output");
const artifact = readJson(input);
const diagnostic = readJson(diagnosticPath);
const generatedAt = "2026-07-18T17:30:00+08:00";
const configuration = diagnostic.scores.configuration;
const taint = diagnostic.scores.taint_flow;
const combined = diagnostic.scores.combined;
const positives = diagnostic.inputs.positive_distribution;
const negatives = diagnostic.inputs.negative_distribution;
const core = new Set([22, 78, 79, 89]);

artifact.manifest.title = "SecMind v0.7 第一版-b：负增长根因、扩展证据与发布判定";
artifact.manifest.description =
  "保留 v0.6 对 Direct 的完整根因诊断，并加入 v0.7 第一版-b 的扩展 CWE 证据、离线候选结果、Direct-first 安全边界和可执行发布门。";
artifact.manifest.generatedAt = generatedAt;
artifact.snapshot.generatedAt = generatedAt;
artifact.manifest.blocks[0].body =
  "# SecMind v0.7 第一版-b：负增长根因、扩展证据与发布判定\n\n面向 Agent 架构、评测与发布负责人；结论严格区分已验证事实、后验候选诊断和仍待配对实验验证的假设。";

const physicalSources = [
  {
    id: "static-signal-diagnostic",
    label: "v0.7 第一版-b 离线静态候选诊断",
    path: "evidence/offline-static-signal-diagnostic.json",
  },
  {
    id: "v07b-design",
    label: "SecMind v0.7 第一版-b 可信增益设计",
    path: "design/SecMind-v0.7-第一版-b-可信增益代码审计设计.md",
  },
  {
    id: "v07b-release-protocol",
    label: "SecMind v0.7 第一版-b 评测与发布协议",
    path: "design/SecMind-v0.7-第一版-b-评测与发布协议.md",
  },
];
artifact.sources.push(...physicalSources);
artifact.manifest.sources.push(...physicalSources);

artifact.snapshot.datasets.v07b_headline_metrics = [
  {
    extended_positive_cases: 29,
    configuration_candidate_tp: configuration.tp,
    configuration_candidate_fp: configuration.fp,
    combined_candidate_recall: combined.recall,
  },
];
artifact.snapshot.datasets.extended_positive_distribution = Object.keys(positives)
  .map(Number)
  .sort((left, right) => left - right)
  .map((cwe) => ({
    cwe: `CWE-${cwe}`,
    positives: positives[String(cwe)],
    negatives: negatives[String(cwe)],
    capability_profile: core.has(cwe) ? "Core" : "Extended only",
  }));
artifact.snapshot.datasets.static_signal_comparison = [
  {
    signal: "保守配置候选",
    tp: configuration.tp,
    fp: configuration.fp,
    fn: configuration.fn,
    precision: configuration.precision,
    recall: configuration.recall,
    f1: configuration.f1,
    authority: "仅触发 Critic",
  },
  {
    signal: "有界污点候选",
    tp: taint.tp,
    fp: taint.fp,
    fn: taint.fn,
    precision: taint.precision,
    recall: taint.recall,
    f1: taint.f1,
    authority: "检索提示",
  },
  {
    signal: "候选并集",
    tp: combined.tp,
    fp: combined.fp,
    fn: combined.fn,
    precision: combined.precision,
    recall: combined.recall,
    f1: combined.f1,
    authority: "诊断口径",
  },
];

const querySources = [
  {
    id: "v07b-headline-sql",
    label: "v0.7 第一版-b 头部指标快照",
    path: "evidence/offline-static-signal-diagnostic.json",
    query: {
      engine: "PostgreSQL-compatible snapshot",
      language: "sql",
      executed_at: generatedAt,
      description: "从 120 题 Gold 分布和离线候选诊断提取扩展范围、配置候选与合并候选指标。",
      sql: "WITH v07b_headline_metrics(extended_positive_cases, configuration_candidate_tp, configuration_candidate_fp, combined_candidate_recall) AS (VALUES (29,19,0,0.6212121212)) SELECT * FROM v07b_headline_metrics",
      filters: [
        "benchmark_cases = 120",
        "network_requests = 0",
        "model_requests = 0",
        "candidate-only diagnostic after gold isolation",
      ],
      metric_definitions: [
        "extended_positive_cases = all positive cases outside CWE-22/78/79/89",
        "combined_candidate_recall = candidate TP / all 66 positive cases",
      ],
    },
  },
  {
    id: "extended-distribution-sql",
    label: "十类 CWE 正负例分布快照",
    path: "evidence/offline-static-signal-diagnostic.json",
    query: {
      engine: "PostgreSQL-compatible snapshot",
      language: "sql",
      executed_at: generatedAt,
      description: "按 CWE 汇总 120 题 Gold 正负例，并标记 Core 与 Extended-only 范围。",
      sql: "WITH extended_positive_distribution(cwe,positives,negatives,capability_profile) AS (VALUES ('CWE-22',7,7,'Core'),('CWE-78',7,5,'Core'),('CWE-79',10,9,'Core'),('CWE-89',13,5,'Core'),('CWE-90',4,1,'Extended only'),('CWE-327',1,7,'Extended only'),('CWE-328',3,9,'Extended only'),('CWE-330',15,5,'Extended only'),('CWE-501',5,6,'Extended only'),('CWE-614',1,0,'Extended only')) SELECT * FROM extended_positive_distribution ORDER BY CAST(REPLACE(cwe,'CWE-','') AS INTEGER)",
      filters: ["benchmark_cases = 120", "gold positives = 66", "gold negatives = 54"],
      metric_definitions: ["positives and negatives are exact case counts per Gold CWE"],
    },
  },
  {
    id: "static-signal-sql",
    label: "静态候选信号比较快照",
    path: "evidence/offline-static-signal-diagnostic.json",
    query: {
      engine: "PostgreSQL-compatible snapshot",
      language: "sql",
      executed_at: generatedAt,
      description: "比较保守配置规则、有界污点规则和候选并集在 Gold 解封后的候选级表现。",
      sql: "WITH static_signal_comparison(signal,tp,fp,fn,precision,recall,f1,authority) AS (VALUES ('保守配置候选',19,0,47,1.0,0.2878787879,0.4470588235,'仅触发 Critic'),('有界污点候选',22,8,44,0.7333333333,0.3333333333,0.4583333333,'检索提示'),('候选并集',41,8,25,0.8367346939,0.6212121212,0.7130434783,'诊断口径')) SELECT * FROM static_signal_comparison",
      filters: [
        "exact CWE match",
        "candidate-only; no Direct or Critic verdict",
        "network_requests = 0",
        "model_requests = 0",
      ],
      metric_definitions: [
        "precision = TP / (TP + FP)",
        "recall = TP / (TP + FN)",
        "F1 = 2TP / (2TP + FP + FN)",
      ],
    },
  },
];
artifact.manifest.sources.push(...querySources);

const newCards = [
  {
    id: "extended-positive-cases",
    description: "原四类能力范围之外的 Gold 正例数量；它们决定总体召回的主要新增空间。",
    dataset: "v07b_headline_metrics",
    sourceId: "v07b-headline-sql",
    metrics: [{ label: "Extended-only 正例", field: "extended_positive_cases", format: "number" }],
  },
  {
    id: "configuration-candidate-tp",
    description: "保守配置规则在解封后的候选诊断中精确命中的正例数。",
    dataset: "v07b_headline_metrics",
    sourceId: "v07b-headline-sql",
    metrics: [{ label: "配置候选 TP", field: "configuration_candidate_tp", format: "number" }],
  },
  {
    id: "configuration-candidate-fp",
    description: "保守配置规则在当前 54 个 Gold 负例中观察到的候选误报数；不构成外部泛化保证。",
    dataset: "v07b_headline_metrics",
    sourceId: "v07b-headline-sql",
    metrics: [{ label: "配置候选 FP", field: "configuration_candidate_fp", format: "number" }],
  },
  {
    id: "combined-candidate-recall",
    description: "配置与污点候选并集覆盖全部 66 个正例的比例；仍需 Direct、Critic 与 GainGate 才能形成最终判断。",
    dataset: "v07b_headline_metrics",
    sourceId: "v07b-headline-sql",
    metrics: [{ label: "合并候选召回率", field: "combined_candidate_recall", format: "percent" }],
  },
];
artifact.manifest.cards.push(...newCards);

artifact.manifest.charts.push({
  id: "extended-positive-distribution",
  title: "120 题各 CWE 正例数量",
  subtitle: "CWE-330 有 15 个正例；原四类之外合计 29 个正例",
  showDescription: true,
  type: "bar",
  intent: "comparison",
  question: "扩展能力范围的评分空间主要分布在哪些 CWE？",
  rationale: "十个离散 CWE 共享同一计数尺度，单序列柱形图可直接显示正例规模，不使用冗余颜色编码。",
  dataset: "extended_positive_distribution",
  sourceId: "extended-distribution-sql",
  encodings: {
    x: { field: "cwe", type: "nominal", label: "CWE" },
    y: { field: "positives", type: "quantitative", format: "number", label: "Gold 正例数" },
    tooltip: [
      { field: "positives", type: "quantitative", format: "number", label: "正例" },
      { field: "negatives", type: "quantitative", format: "number", label: "负例" },
      { field: "capability_profile", type: "nominal", label: "能力范围" },
    ],
  },
  layout: "full",
  maxRows: 20,
});

artifact.manifest.tables.push({
  id: "static-signal-comparison",
  title: "离线静态候选信号表现",
  subtitle: "Gold 解封后的工程诊断；候选不是权威 Agent 预测",
  showDescription: true,
  dataset: "static_signal_comparison",
  sourceId: "static-signal-sql",
  defaultSort: { field: "precision", direction: "desc" },
  density: "spacious",
  layout: "full",
  columns: [
    { field: "signal", label: "信号", type: "text" },
    { field: "tp", label: "TP", format: "number" },
    { field: "fp", label: "FP", format: "number" },
    { field: "fn", label: "FN", format: "number" },
    { field: "precision", label: "Precision", format: "percent" },
    { field: "recall", label: "Recall", format: "percent" },
    { field: "f1", label: "F1", format: "percent" },
    { field: "authority", label: "线上权限", type: "text" },
  ],
});

artifact.manifest.blocks.push(
  {
    id: "v07b-update",
    type: "markdown",
    body: "## 第一版-b 的增量结论\n\n四类范围的理论总体 F1 上限只有 71.84%，而 Direct 完整轮已达 70.59%，所以继续增加规划或反思层没有足够评分空间。第一版-b 将能力范围扩展到十类 CWE，并把新增信息分成两级：保守配置证据优先触发 Critic；误报较高的污点候选只用于检索与冲突定位。默认仍为 shadow，未通过配对实验的增强不会覆盖 Direct Baseline。",
    sourceId: "v07b-design",
    layout: "full",
  },
  {
    id: "v07b-metric-strip",
    type: "metric-strip",
    cardIds: newCards.map((card) => card.id),
    layout: "full",
  },
  {
    id: "extended-distribution-intro",
    type: "markdown",
    body: "## 评分增量主要来自扩展范围\n\n66 个 Gold 正例中有 29 个不属于 CWE-22/78/79/89。CWE-330 单类就有 15 个正例，是最明确的新增召回空间；配置规则还能覆盖弱密码、弱哈希和显式不安全 Cookie。",
    sourceId: "extended-distribution-sql",
    layout: "full",
  },
  { id: "extended-distribution-chart-block", type: "chart", chartId: "extended-positive-distribution", layout: "full" },
  {
    id: "candidate-boundary",
    type: "markdown",
    body: "## 高精度配置候选值得实验，通用污点候选不能直接晋升\n\n保守配置候选命中 19 个正例且当前观察到 0 个误报；这 19 个命中全部来自原四类之外。相对地，有界污点候选为 22 TP/8 FP，候选并集虽覆盖 62.12% 正例，但 Precision 只有 83.67%。因此线上权限必须不同：配置候选进入独立 Critic，污点候选只提供最小代码切片；两者都不能绕过语义证书和 GainGate。",
    sourceId: "static-signal-sql",
    layout: "full",
  },
  { id: "static-signal-table-block", type: "table", tableId: "static-signal-comparison", layout: "full" },
  {
    id: "v07b-release-decision",
    type: "markdown",
    body: "## 发布判定：架构优于 v0.6，但认知优于 Direct 仍待证明\n\n可靠性方面，Direct-first、逐单元提交和 shadow 权威选择已经针对 v0.6 的中断负增长；增强失败时返回 Baseline。认知方面，19 TP/0 FP 只是后验 candidate-only 证据，不能与 Direct TP 简单相加。Authoritative 必须同时满足：扩展范围 ΔF1≥3pp、paired bootstrap 95% CI 下界大于 0、Precision≥95%、Recall 不低于 Direct、原四类不新增 FP/FN、Coverage≥98%、完成率 100% 和 RECOVERY_REQUIRED=0。",
    sourceId: "v07b-release-protocol",
    layout: "full",
  },
  {
    id: "v07b-known-unknowns",
    type: "markdown",
    body: "## 尚未解决的证据缺口\n\n- 当前 Java flow slicer 是有界启发式，不是编译器级跨方法证明；解析失败和动态语义必须保持 inconclusive。\n- 公开 120 题上的候选效果可能过拟合，至少需要 300 个私有、重命名或等价扰动样本。\n- 当前没有真实 API，因此没有使用模型，也没有产生 live v0.7 配对分数。\n- 下一轮在线测试最高使用 5.4；5.6、未知模型和未经许可的 Base URL 均被硬闸拒绝。",
    sourceId: "v07b-design",
    layout: "full",
  },
);

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
