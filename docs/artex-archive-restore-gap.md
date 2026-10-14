# ARTEX M6 归档与恢复：学习差距、契约与实施计划

## 文档目的

这份文档把 ARTEX 的任务归档/恢复机制整理成 SecMind 可以实现和验收的 M6 计划。它描述要学习的行为契约，不要求复制 ARTEX 的 Go 文件或 PostgreSQL 表结构。

ARTEX 对照版本：`ce42b66a6b1f8150380f2cbdedcd98b34d4bd404d56869ada31a67f0671475c3`。主要来源：

- `db/task_archives.go`
- `db/task_archives_restore.go`
- `server/task_archive_package.go`
- `server/task_archive_package_test.go`

ARTEX 根目录许可证为 AGPL-3.0。SecMind 采用 Python/SQLAlchemy 的行为重写；如果以后直接移植代码，必须逐文件记录来源版本、版权、许可证和改动，并按 AGPL-3.0 履行相应义务。

## 从 ARTEX 学什么

### 1. 归档前先冻结，再拍摄一致快照

ARTEX 只允许暂停或终态任务进入归档。数据库使用 repeatable-read、只读事务，同时把任务、探索图、资产、用量、技能/工具记录、旁路问答和拦截记录纳入同一个快照。大型 `llm_records` 以 JSONL 流式写出，但仍与其它表使用同一数据库快照。

SecMind 需要把“可归档”定义为运行状态和租约状态的契约，而不是调用方自行决定。冻结结果应包含运行状态、最新账本序号、状态版本、检查点引用和资产清单；冻结期间拒绝新的执行写入，或明确把迟到写入标记为归档外事件。

### 2. manifest 是恢复协议，不是目录说明

ARTEX 的 `manifest.json` 使用显式格式版本（当前 v3，兼容 v1），并保存任务/探索身份、来源任务、主机与独占资产、表数据、流式表路径、各表数量和聚合统计。数据库记录另外保存归档包 SHA-256、原始大小、压缩大小和状态。

SecMind 的 manifest 应覆盖每一项可恢复材料：运行状态、账本事件、审计对象、模型/工具回执、上下文包、检查点引用、artifact 元数据及外部 blob。每项都要有规范化路径、媒体类型、字节数和 SHA-256；manifest 自身也必须进入清单并参与顶层摘要。

### 3. 文件移动必须可回滚，发布必须原子化

ARTEX 在移动任务目录和 transcript 前先写 journal，按计划执行 rename；中断后依据 journal 回滚或继续。压缩包先写 `.partial`，完成同步和校验后再 rename 为正式路径。恢复文件也先记录 journal，目标已存在时拒绝覆盖。

SecMind 的实现应复用 `ContentAddressedArtifactStore` 的临时文件、fsync、校验和原子替换语义，增加归档 staging 目录与 journal。不能用“先删源文件、最后再写 manifest”的不可恢复流程。

### 4. 恢复要处理身份映射和缺失全局对象

ARTEX 不假设数据库自增 ID 可以原样搬回。资产先按自然键匹配；ID 被占用时分配新 ID，再重写锚点、任务资产链接、节点 payload 和 finding 中的资产引用。分类、公司、LLM profile 等全局对象缺失时记录 warning，不伪造对象。来源任务不存在时跳过继承关系并记录 warning。

SecMind 需要把 `run_id`、`artifact_id`、`event_id`、`checkpoint_id` 等身份分成“归档内稳定 ID”和“恢复目标 ID”。恢复必须生成一份完整 mapping，并在所有引用重写完成前禁止提交；无法映射的引用要失败或进入明确的 warning/quarantine 状态，不能静默丢失。

### 5. 恢复接口要有 allowlist、幂等和执行隔离

ARTEX 只允许固定表集合进入恢复，未知表直接拒绝。重复恢复由状态机和已存在的 archived stub 阻止；校验失败、缺少流式文件、行数与 manifest 不符都会回滚事务。恢复只还原数据和任务状态，不自动重新执行任务；归档期间未完成的审批被转成超时或未知结果。

SecMind 必须把恢复视为离线导入：不创建新的 dispatch permit，不领取 worker lease，不调用模型/工具，不重放付费请求。恢复成功后只能进入待人工复核或明确的暂停状态；需要继续执行时必须由新的计划和新的授权显式启动。

## SecMind 当前基础与缺口

已有能力：

- `LedgerStore` 保存按 run 分区的 hash-chain 事件，支持 dedupe key、`verify()`、状态快照和 CAS 版本。
- `ContentAddressedArtifactStore` 使用完整 SHA-256 作为不可变 artifact 身份，写入时校验大小和摘要，并用临时文件与原子替换避免半文件。
- `AuditPersistence`、`InvestigationStore` 和 `AgentState` 已有对象摘要、权限标签、schema upcast、fencing 和恢复边界。
- `AgentState` 记录运行状态、账本相关引用、上下文包、审计对象、检查点相关字段和完成状态。

当前缺口：

1. 没有跨 `RunRow`、ledger、investigation 对象、artifact blob 和 LangGraph checkpoint 的统一归档清单。
2. 没有冻结协议来阻止归档期间的执行写入或界定迟到写入。
3. 没有每个归档成员的路径、大小、SHA-256、媒体类型和来源版本清单。
4. 没有隔离恢复目录、恢复 journal、缺件/篡改/重复恢复的统一错误模型。
5. 没有恢复目标 run 的新身份和引用重写协议；现有 `run_id` 不能直接假设跨环境唯一。
6. 没有把恢复和“继续执行”硬隔离的服务边界及契约测试。
7. 现有 artifact 分类保证访问策略，但还没有把分类 marker、外部 blob 和 ledger/state 一起纳入归档一致性证明。

## 当前实现进度

已加入 `secmind/src/secmind/archive_restore.py` 和对应契约测试：

- `export_run_archive(...)` 从现有 `LedgerStore` 导出 state 与完整 hash-chain JSONL，并记录状态版本、最新序号和链头哈希。
- 从 `ContentAddressedArtifactStore` 读取 artifact bytes 与分类 metadata；成员路径、大小、SHA-256、媒体类型和数量进入 manifest。
- 导出拒绝运行中状态和无效账本；归档目录只在新建或空目录中发布。
- 恢复增加目标锁、持久 `.restore-journal.json` 和 staging 目录；进程中断后下一次恢复先清理 journal 记录的半成品，再重新安装。
- 重复恢复仍由 `.restore-complete.json` 幂等保护，恢复结果继续固定为 `execution_allowed=false`。

这些内容完成了 M6.2 的 manifest/成员校验基础和 M6.3 的本地 staging/journal 基础。冻结期间写入 fencing、真实 run/artifact/event/checkpoint ID 重写、数据库事务接入、恢复后的服务状态隔离和跨服务故障矩阵仍未完成，不能把 M6 标记为完成。

## 首期 M6 契约

### 归档清单建议结构

以下是行为契约草案，字段名可在实现时调整，但语义必须保留：

```json
{
  "format_version": 1,
  "archive_id": "archive-...",
  "created_at": "UTC timestamp",
  "source": {
    "run_id": "run-...",
    "state_version": 12,
    "latest_event_sequence": 48,
    "checkpoint_ref": "...",
    "schema_version": "..."
  },
  "freeze": {
    "freeze_id": "freeze-...",
    "status": "paused|terminal",
    "frozen_at": "UTC timestamp",
    "ledger_head_hash": "sha256",
    "artifact_snapshot_digest": "sha256"
  },
  "members": [
    {
      "path": "ledger/events.jsonl",
      "kind": "ledger|state|audit|artifact|checkpoint|metadata",
      "media_type": "application/json",
      "size_bytes": 123,
      "sha256": "64 lowercase hex",
      "source_id": "...",
      "schema_version": "..."
    }
  ],
  "id_map": {"source_run_id": "restored_run_id"},
  "counts": {"ledger_events": 48, "artifacts": 7},
  "warnings": []
}
```

`members` 必须排序后再序列化；路径只能位于归档根目录，拒绝 `..`、绝对路径、符号链接和未知 kind。manifest 的 canonical JSON 摘要用于检测清单自身变化。归档包外层可以采用 tar+zstd，也可以先用目录格式完成契约测试；压缩算法不是 M6 的核心行为。

### 状态与错误行为

| 场景 | 预期行为 |
|---|---|
| 运行中、租约未释放 | 拒绝冻结，保留原运行 |
| 成员缺失 | 恢复前失败，目标库无部分提交 |
| 成员 SHA-256 或大小不符 | 拒绝恢复并隔离损坏包 |
| manifest 版本不支持 | 拒绝恢复并给出可诊断错误 |
| 未知成员 kind/path | 拒绝恢复，不执行动态导入 |
| 目标 run 已存在同一 archive_id | 返回幂等成功或明确“已恢复”，不得重复插入 |
| 目标 run 已存在不同 archive_id 但同 run_id | 分配新 run ID 或拒绝，不能覆盖 |
| 引用对象无法映射 | 事务回滚；若契约允许 warning，必须保留 warning 和 quarantine 标记 |
| 恢复后发现可执行状态 | 强制转为 paused/recovery_required，不创建执行授权 |
| 恢复进程中断 | 依据 journal 回滚或继续，重启后不会留下半安装文件 |

## 实施顺序与验收门槛

| 工作包 | 产物 | 验收门槛 |
|---|---|---|
| M6.1 范围与冻结 | `ArchiveScope`、冻结状态机、写入 fencing 规则 | 运行中/租约中拒绝；冻结时记录 state version、ledger head 和 checkpoint ref |
| M6.2 manifest 与清单 | 版本化 manifest、canonical 序列化、成员 hash/size/count | 同一固定 fixture 多次生成完全一致；成员增删和内容变化必然改变摘要 |
| M6.3 staging 与发布 | 临时目录、journal、原子发布、路径安全校验 | 中断后可回滚；半包和 traversal/symlink 被拒绝；正式包不暴露半成品 |
| M6.4 隔离恢复 | 新 run 身份、artifact/ledger/state 导入、引用 mapping | 恢复到空目标后数量、hash、链头和引用一致；不覆盖现有数据 |
| M6.5 幂等与兼容 | archive_id 记录、格式版本矩阵、重复恢复处理 | 同包重复恢复不重复事件/artifact；旧版本只按显式迁移规则读取 |
| M6.6 执行隔离 | restore service guard、状态降级、审批/回执处理 | 恢复过程无模型/工具/dispatch/lease 调用；恢复后继续执行必须新授权 |
| M6.7 故障回归 | 固定 JSON/artifact fixture、操作说明、审计来源记录 | 缺件、篡改、重复、ID 冲突、中断、迟到写入均有可观察结果 |

首期先实现目录格式和本地 fixture；确认契约后再选择压缩包格式和远端对象存储适配。不要把 tar/zstd、PostgreSQL `json_populate_recordset` 或 ARTEX 的表名直接移植进 SecMind。

## 最小契约测试清单

建议新增 `secmind/tests/test_archive_restore_contract.py`，只使用临时目录、内存/SQLite LedgerStore 和固定 artifact bytes：

1. manifest 成员排序和 canonical digest deterministic。
2. 每个成员的 byte count、SHA-256 和总数量完整。
3. 删除成员、修改成员、修改 manifest、修改 artifact marker 都会被拒绝。
4. `..`、绝对路径、符号链接和未知 kind 都会被拒绝。
5. 同一 `archive_id` 重复恢复不产生第二份 ledger event 或 artifact。
6. 目标已有不同 run 时生成新 ID mapping，所有跨对象引用使用 mapping 后一致。
7. 恢复事务中途失败时目标状态、事件和 artifact 均无半提交。
8. 恢复后的状态不能创建工具调用、模型请求、lease 或 dispatch permit。
9. 旧 manifest 版本按迁移表升级；不支持版本明确失败。
10. 冻结后写入被拒绝或进入明确的迟到事件隔离区。

## 暂不进入 M6 的内容

- 不复制 ARTEX 的 Go 归档 worker、HTTP handler 或 PostgreSQL 表结构。
- 不把冷摘要重新生成写入归档；归档保存摘要 provenance 和原始成员，摘要仍是派生视图。
- 不在恢复阶段自动重新运行失败步骤、补发模型请求或恢复待审批工具执行。
- 不把 ARTEX 的 `category/company/llm_profile` warning 语义机械套到 SecMind；SecMind 应按自己的 artifact 权限标签、外部引用和运行授权模型定义缺件处理。

## 当前结论

ARTEX M6 最值得学习的是“可证明的恢复边界”：冻结快照、显式清单、逐项校验、可回滚 staging、身份映射和执行隔离必须作为一个协议一起实现。SecMind 已经有 hash-chain ledger、CAS 状态和 content-addressed artifact 三个基础件，下一步应先补统一 manifest 与冻结/恢复契约，再实现服务和页面。M6 完成的标志是上述故障矩阵和契约测试通过，而不是归档文件能够成功生成。
