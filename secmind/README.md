# SecMind

当前代码包版本为 **0.8.7**（以 `src/secmind/__init__.py` 为准），公共 Schema 为 1.7。统一套件的当前接入、运行状态和 2026-10-01 验收见 [套件完善记录](../docs/completion-2026-10-01.md)。下面的 v0.8.5 发布说明是历史记录，其中测试和评测数字不代表当前 Windows 部署已经完成同等验证。

## v0.8.5 历史发布说明

> **v0.8.5 可信调查内核候选版**：在 v0.8.4 的 typed-domain 与 Direct Anchor
> 基础上，进一步统一任务合同、答案义务和版本化修订，补齐 observation-driven EIRS、
> 跨域受控检索、模型分阶段期限、可恢复 Outbox、Finding 级隔离以及真实 rootless 工具保证。
> 80 例冻结工具 holdout 已由平台签名重放，8/8 工具的 precision/recall（或 SBOM
> completeness/accuracy）均为 `1.0`；工程门为 1,650 项测试零失败、综合覆盖率
> `85.807%`、分支覆盖率 `75.658%`。在线 Luna 发布分数只在 clean commit 评测完成后写入
> [v0.8.5 发布证据](docs/v0.8.5-release-evidence.md)。

> 2026-07 审核加固：Direct 质量主审已纳入正式 `PlanContract -> TeamPlan -> PrimaryAuditAgent`
> 主链；模型证据与语义证据分级，Reducer 会融合跨工具证据，GainGate 支持经密封评测批准的双向纠错，
> 权威评分使用 exact-CWE F1。详见 [Agent 效果与架构加固](docs/v0.7-agent-effect-hardening.md)。

SecMind 是面向代码安全审计的可信 Agent 运行内核。v0.8 保留 Direct 锚定的强
Primary，将可选工具与 Agent 限定为由 typed evidence gap 触发的局部 patch；
`AdmissionService` 是唯一能改变公开 Finding 集合的权威，Reporter 只渲染密封投影。

当前 Python 包版本为 `0.8.5`，运行时公共 Schema 为 `1.7`，Alembic head 为
`0021_outbox_quarantine_proj`。v0.8.5 使用独立 Test3 Bridge 契约层保留领域、评分模式、
typed answer、Evidence 和安全诊断；发布声明仅覆盖相同评测程序中的 v0.8.3 配对回归，
不把单轮在线模型结果解释成 Agent 相对任意 Direct 配置的普遍因果优势。

本轮 29 项审查结论、实现位置与验收证据见
[v0.8.5 审查闭环矩阵](docs/v0.8.5-completion-matrix.md)。

默认 `SECMIND_AUDIT_KERNEL_MODE=shadow`：用户可见结果保持 Direct-first baseline，
候选增强只进入独立 shadow lane。只有冻结版本通过配对发布门后，才应显式切换为
`authoritative`。

## v0.8 可信增益主链

```text
PlanContract + TeamPlan
  -> sealed PrimaryAuditAgent WorkItem
  -> dependency-closed immutable AuditUnit shards
  -> persist positive / negative / inconclusive baseline
  -> collect deterministic Java flow evidence
  -> invoke Critic only for an eligible conflict or gap
  -> structural consistency certificate
  -> bidirectional asymmetric GainGate
  -> persist final/shadow UnitDecision and partial-capable report
```

- `PrimaryVerdict` 显式记录 `vulnerable`、`not_vulnerable` 或 `inconclusive`；负结论是
  一等记录，不能再从“没有 Finding”反推。
- `UnitDecision` 同时保留 baseline/final verdict、模型 receipt、Evidence、原因和 digest。
- `GainGate` 同时支持补漏和纠正误报，但删除/降级使用更高阈值。两种方向都必须满足固定策略、
  获批工具流、有效结构一致性证书、不同模型血缘的 Critic、证据完整性和未过期的精确
  `PatchReleaseRecord`；缺少服务端密封评测发布记录时始终保持 Direct 锚定基线。
- 策略无效、工具/Critic 异常、证据不足或语义检查失败时一律 `KEEP_BASELINE`；接受增强
  时 Evidence 只能增加，不能抹除基线证据。
- Review shard、PrimaryVerdict 和 UnitDecision 可独立持久化并幂等恢复；单个 item/shard
  失败不会回滚已提交单元。
- 一次运行只消费由 `started_at + max_runtime_seconds` 得到的绝对 `deadline_at`。到期后
  停止新模型调用，并用已提交单元形成 partial 结果，而不是续订墙钟预算。

## 模型与成本硬闸

- 默认 `SECMIND_MODEL_MODE=offline`，不会发起真实模型请求或产生真实模型费用。
- `mock` 必须注入 `httpx.MockTransport` 测试客户端，普通网络 Transport 会启动失败；`live` 必须显式允许并同时满足非 demo、凭据、HTTPS 和
  Base URL allowlist。
- 模型目录是闭集，未知模型直接拒绝。通用高成本模型仍受 **5.4** 档位硬闸约束；
  用户指定的成本敏感 `gpt-5.6-luna` 以独立低成本目录项接入，必须同时满足 live 开关、
  HTTPS Base URL allowlist、预算和完整运行身份，不能借版本号绕过成本等级。
- fallback 不得比 planner/worker 更昂贵；CI 和离线回放应保持真实请求数与费用为 0。

## 核心能力

- FastAPI 控制面：任务、运行状态、审批、报告、证据、账本、产物和 WebSocket 事件。
- 持久 Coordinator：PostgreSQL 队列、lease、fence、CAS、幂等恢复和有界重试。
- 受控多智能体：计划校验、DAG 调度、专业 Worker、确定性归并和独立证据验证。
- 原子执行平面：Policy/Guardrail、预算、审批、Invocation、Runner 和 ArtifactStore。
- 可信证据链：Finding、Evidence、内容哈希、Outbox、append-only 账本和完成收据。
- 安全沙箱：固定镜像、无网络、只读 rootfs、非 root、能力清零和资源限制。
- 提示词智能层：Canonical Primary 已通过持久化 `PromptArtifact` 进入模型网关；
  fixed 模式保持 v0.7.1 canonical v2 的 system/user/schema 请求等价。69 条自适应策略与
  195 条生命周期策略仍需通过配对发布门才能进入权威热路径。
- 主动 Skill/工具融合：六个签名 L4 Skill 强制绑定 PlanStep、WorkItem 与工作合同；273 张
  固定来源的外部方法卡仅以 L5 不可信知识参与路由，不执行上游脚本。

## 仓库结构

```text
src/secmind/audit_kernel/  v0.7 合约、Reviewer、GainGate、持久化与流水线
src/secmind/prompting/     提示词 Context、Catalog、Selector、Compiler、Policy 与 Store
src/secmind/external_skills.py  外部 Skill 锁定目录、选择与主动绑定
src/secmind/               API、Coordinator、Broker、证据与既有运行时
migrations/                PostgreSQL/Alembic 迁移链
docker/                    sandbox-runner、staging helper 与工具镜像
contracts/                 v1.1—v1.6 兼容快照与冻结的 v1.7 Schema/OpenAPI golden
scripts/                   启动、Docker 初始化和 v0.7 离线评测脚本
docs/                      架构、公共契约、评测协议和设计边界
```

## Docker 一键启动

需要 Docker Engine（Windows 开发宿主可使用 Docker Desktop）和 Docker Compose：

```powershell
Copy-Item .env.example .env
.\scripts\bootstrap-docker.ps1
```

脚本会生成本地控制令牌、构建固定 Bandit/staging 镜像并启动 API、Worker、
Outbox Projector、PostgreSQL 与 sandbox-runner。启动后访问：

- API 文档：`http://127.0.0.1:8000/docs`
- 存活检查：`http://127.0.0.1:8000/health/live`
- 就绪检查：`http://127.0.0.1:8000/health/ready`

比赛部署使用叠加配置，并必须提供独立 rootless Docker socket、operator token、
Ed25519 ticket 密钥和固定 digest 的工具镜像：

```powershell
docker compose -f docker-compose.yml -f docker-compose.competition.yml up --build -d
```

## 本地离线启动

```powershell
uv sync --frozen
Copy-Item .env.example .env
$env:SECMIND_MODEL_MODE = "offline"
$env:SECMIND_UNSAFE_DEVELOPMENT_TOOLS = "true"  # 仅限本地开发
uv run alembic upgrade head
uv run secmind-api
```

生产或比赛环境禁止宿主 subprocess fallback；Runner、ticket 密钥或固定镜像不完整时
系统会失败关闭。

## 主要接口

- `POST /api/v1/tasks`、`GET /api/v1/runs`、`GET /api/v1/runs/{run_id}`
- `GET /api/v1/runs/{run_id}/report`、`/ledger`、`/evidence-graph`
- `POST /api/v1/runs/{run_id}/approvals/{request_id}`、`/cancel`、`/recover`
- `GET /api/v1/runs/{run_id}/artifacts/{artifact_id}`、`GET /api/v1/tools`
- `GET /api/v1/runs/{run_id}/units`、`/comparative-result`
- `GET /api/v1/runs/{run_id}/evidence-gaps`、`/admission`
- `GET /api/v1/runs/{run_id}/session`：强类型多步骤状态、恢复建议和工具/证据生命周期投影
- `GET /api/v1/patch-releases`、`POST /api/v1/patch-releases/{id}/revoke`
- `GET /api/v1/prompts/templates`、`POST /api/v1/prompts/preview`
- `GET /api/v1/runs/{run_id}/prompt-artifacts`
- `GET /api/v1/skills/external`、`GET /api/v1/runs/{run_id}/skills`
- `WS /api/v1/runs/{run_id}/events`

REST/OpenAPI 仍保持 `/api/v1` 路径；新生成对象的 `schema_version` 为 `1.7`。
[`contracts/public-v1.6.json`](contracts/public-v1.6.json) 作为 v0.7 集成兼容快照保留。
冻结的 v1.7 契约见 [`contracts/public-v1.7.json`](contracts/public-v1.7.json) 和
[公共接口契约](docs/contracts.md)。

## 安全边界

- 专业 Agent 不能绕过 Coordinator、Policy、Budget 或 Tool Broker。
- R2 操作必须审批，R3 操作直接拒绝；审批与 run、step、参数哈希和 fence 绑定。
- 源代码、检索内容和工具输出始终是不可信数据，不能修改系统策略或授权范围。
- API/模型密钥不会进入工具容器；敏感字段统一经过 SecretScrubber。
- 所有结论必须绑定可复验 Evidence，不保存或展示隐藏思维链。

## 正式文档

- [版本变更记录](CHANGELOG.md)
- [v0.8：基于 clean v0.7.1 实测的可信增益架构定稿](docs/v0.8-v071-live-refined-design.md)
- [逆向分析环节状态表](reverse_analysis_process_status_table.md)
- [DeepSeek API 可靠性优化后测评交付（2026-08-25-v3，48 槽位全产出）](docs/reports/reverse-analysis-deepseek-api-2026-08-25-v3/index.html)
- [维护者指南：代码地图、常见修改与验证](docs/maintainer-guide.md)
- [渐进式可维护性重构方案](docs/codebase-refactoring-plan.md)
- [v0.7 Direct-first 架构](docs/v0.7-architecture.md)
- [v0.7 离线评测与发布门](docs/v0.7-evaluation-protocol.md)
- [v0.7 发布就绪、限制与回滚](docs/v0.7-release-readiness.md)
- [v0.7 自适应提示词智能层](docs/v0.7-prompt-intelligence.md)
- [v0.7 可信 Skill 与工具融合](docs/v0.7-skill-integration.md)
- [工具激活、并行覆盖与未调用原因](docs/tool-activation.md)
- [v0.7 完成度审核](docs/v0.7-completeness-audit.md)
- [v0.7 实验运行手册](docs/v0.7-experiment-runbook.md)
- [v0.6 可信调查架构](docs/v0.6-trusted-investigation-architecture.md)
- [公共接口契约](docs/contracts.md)
- [ADR-0601：独立认知内核](docs/adr/ADR-0601-omo-inspired-independent-cognition.md)
- [设计来源与独立实现边界](DESIGN_INSPIRATIONS.md)
- [第三方组件声明](THIRD_PARTY_NOTICES.md)

## 验证状态与发布门

当前已具备离线/Mock 的确定性验证、冻结 receipt 回放、真实 PostgreSQL、rootless Runner
及 Tool Assurance 验收。在线发布仍使用完全相同的输入、模型、Prompt、预算、绝对
deadline 与重试规则做配对评测，并报告 Precision、Recall、F1、Coverage、完成率、
逐领域退化、成本和 `RECOVERY_REQUIRED`。在 clean-identity Luna 发布实验通过前：

- Direct specialist 仍是效果基线；v0.7 应按 Baseline/Shadow 候选评估。
- `authoritative` 配置能力不代表已经满足发布门；无正增益 receipt 时 Prompt optimizer
  自动保持 shadow。
- 不得把未配对的单轮高分宣传为统计显著优于 Direct。
