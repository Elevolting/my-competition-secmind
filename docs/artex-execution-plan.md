# SecMind 学习 ARTEX：执行版计划

## 目标

从 ARTEX 提取可验证的行为契约，补强 SecMind 的长期任务、证据追溯、恢复和外部资产接入能力。优先复用 SecMind 现有的账本、CAS artifact、AgentState、模型网关和 MCP，不复制 ARTEX 的 Go 文件、数据库表或 HTTP 层。

ARTEX 对照版本：`ce42b66a6b1f8150380f2cbdedcd98b34d4bd404d56869ada31a67f0671475c3`。ARTEX 根目录为 AGPL-3.0；任何直接移植都必须保留版权和许可证说明，记录来源版本、文件、改动，并履行 AGPL-3.0 的对应义务。默认采用行为重写。

## 优先级

| 优先级 | 学习主题 | 主要收益 | 进入实现的条件 |
|---|---|---|---|
| P0 | 事件、证据与任务身份 | 能从结论回到原始执行、请求/响应和复核材料 | 已有基础，持续作为所有阶段的共同约束 |
| P0 | 跨轮规划与持久状态 | 重启、失败和分支执行后仍能知道下一步 | 先完成当前 Planner/黑板缺口盘点 |
| P0 | 冷热图、摘要和上下文预算 | 长任务降低上下文成本，同时保留原始节点 | M5.3 已接入，先补模型网关、两侧运行时和故障回归 |
| P0 | 归档、冻结与隔离恢复 | 可备份、迁移、复查，恢复不会误执行 | 先完成 M6 契约，再接服务/API |
| P1 | 技能加载与工具调用留痕 | 区分选中、加载、调用、重试和结果 | 找到真实加载及 `tool.invoke()` 边界 |
| P1 | 旁路问答的请求快照 | 查询运行依据而不改变主任务 | 绑定真实模型请求边界和独立预算 |
| P1 | 持久通知与领取租约 | 审批、预算和终态事件可恢复投递 | M7 只先做站内通知 |
| P1 | ScopeSentry 分页同步 | 外部资产有预览、范围校验和幂等导入 | 确认 MCP/schema 版本，复用 M1 身份 |
| P2 | 审批上下文来源约束 | 避免把工具参数、人类选择和审计历史混为一谈 | 先用固定样例复现真实缺口 |
| P2 | 模型池共享健康状态 | 减少跨任务故障放大和重复输出/计费 | 先复现现有重试问题，再决定立项 |

## 学习方法

每个主题固定走六步：

1. 阅读 ARTEX 源码和测试，写出输入、状态、输出、失败和恢复语义。
2. 对照 SecMind 现有模块，列出可复用能力和真实缺口。
3. 先写固定 fixture、数据契约和故障矩阵，再写最小实现。
4. 优先用 Python/SQLAlchemy/React 重写行为；只有确有必要时才直接移植代码。
5. 完成后端、前端、重启/并发/损坏材料回归及文档，再独立提交。
6. 记录来源版本、许可证、版权、改动和未实现的 ARTEX 语义。

## 实施顺序

### 阶段 0：基线与边界

**产物：** ARTEX 对照版本、SecMind 现状清单、共享术语、来源/许可证记录模板。

**完成标准：** 每个后续工作包都有 ARTEX 文件、SecMind 落点、不可移植部分和验收场景；不调用真实付费模型，不重启现有服务。

### 阶段 1：完成 M5 冷节点摘要

**学习重点：** `agent/coldgraph.go`、`db/digest.go` 的冷热节点、稳定分组、成员/锚点引用、签名失效和上下文裁剪。

**实现顺序：**

1. 补齐状态枚举和 settled 白名单对照。
2. 把 content version、source refs 和签名接入生成器。
3. 接通真实模型网关的预算、失败和迟到回调隔离。
4. 完成两侧运行时、前端折叠/展开/搜索和固定 token 基线。

**验收：** 原节点可展开；活跃分支不被折叠；内容变化使摘要失效；失败不丢原记录；上下文 pack 可复现并有可测预算收益。

### 阶段 2：完成 M6 归档与恢复

**学习重点：** `db/task_archives.go`、`db/task_archives_restore.go`、`server/task_archive_package.go` 及 package tests。

**实现顺序：**

1. 冻结运行、租约和写入 fencing。
2. 设计版本化 manifest，覆盖 state、ledger、审计对象、artifact、checkpoint 和外部 blob。
3. 实现 staging journal、原子发布、路径/符号链接/未知成员拒绝。
4. 导出 ledger、state 和 artifact metadata，验证 hash-chain 与数量。
5. 隔离恢复，生成 run/artifact/event/checkpoint ID mapping 并重写引用。
6. 增加重复恢复、崩溃重启、缺件/篡改/冲突和执行隔离测试。

**验收：** 同一归档重复恢复幂等；恢复后数量、哈希、引用和链头一致；恢复不领取 lease、不创建 dispatch、不调用模型或工具；中断后可回滚或继续。

### 阶段 3：M7 持久通知

**学习重点：** `db/notification_delivery.go`、`server/notifier.go` 的事件去重、租约、重试和终态处理。

**实现顺序：** 稳定事件源 → durable outbox → 领取/续租/有限重试 → 站内收件箱和已读 → 崩溃与重复投递回归。

**验收：** 重复事件不重复通知；刷新和重启保留已读/未读；租约过期可恢复；通知能跳回原任务和事件。

### 阶段 4：M8 外部资产同步

**学习重点：** `server/sync_scopesentry.go` 的分页、游标、范围映射和差异处理。

**实现顺序：** MCP/schema 对照 → 分页 fixture → 差异预览 → 授权范围校验 → 幂等导入 → 部分失败恢复。

**验收：** 预览和正式导入分离；越界目标阻止；重复导入不增加资产；来源和页码可追溯；部分失败可继续。

### 阶段 5：条件能力评估

先不实现审批上下文约束和模型池健康共享。各自完成固定样例和收益/风险记录；只有证明现有系统存在决策误用、重试放大、重复输出或重复计费，再立项并沿用阶段 0 的契约流程。

## 每阶段的交付清单

- ARTEX 源码/测试阅读笔记和对照版本。
- SecMind 数据契约、迁移说明和兼容矩阵。
- 最小实现、固定 fixture、故障矩阵和操作说明。
- 许可证/版权/来源/改动记录。
- Python 检查、前端检查、集成回归和 `git diff --check` 结果。
- 独立 Git 提交；提交信息说明行为变化和验证范围。

## 当前执行点

路线文档和 M6 差距审计已提交。M6 文件级归档契约、`LedgerStore`/`ContentAddressedArtifactStore` 真实导出、目标锁、持久恢复 journal、文件级 run 映射，以及 checkpoint JSONL、稳定 digest、schema version、LangGraph adapter 和 checkpoint ID mapping 已完成并有固定 fixture。M6.1 冻结协议已落地：`run_archive_freezes` 持久记录在 ledger 边界写入 `archive.freeze_started` 事件；`append`、`save_state`、`save_state_cas`、CAS artifact `put/classify`，以及 Coordinator 和 InvestigationStore 的 lease、step、outbox、model/tool、对象、用量、dispatch、审批、恢复命令、消息和完成凭据写入，在 pending/complete 冻结期间拒绝写入；artifact/checkpoint 快照摘要和 ledger 头在完成冻结时再次校验。应用运行时 checkpointer 已统一经 `FencedCheckpointSaver` 写入代理，并在写入前查询持久 archive freeze。checkpoint 专项测试覆盖确定性、重复 ID、二进制值、run/checkpoint 重映射、缺少 adapter、篡改、恢复失败清理和 fencing。下一步补跨数据库原子 fencing、数据库事务中的 artifact/event/checkpoint 冲突处理、PostgreSQL 事务快照、完整 ID mapping 和恢复后的服务状态隔离，再做跨服务故障矩阵。

