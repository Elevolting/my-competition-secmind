# M5 冷节点摘要：差距与数据契约

## 文档目的

这份文档把 ARTEX 的冷节点摘要设计转换成 SecMind 可以审查和分阶段实现的契约。源码对照与差距定义已完成，工作区已有显式迁移、真实 planner round 投影和局部夹具；模型上下文接入仍待验收，不把现有 `ContextManager` 的上下文裁剪或页面折叠标记为冷节点摘要完成。执行顺序与草稿待办见 [学习计划](artex-learning-plan.md)。

## 来源与重写边界

| 项目 | 内容 |
|---|---|
| ARTEX 来源 | `agent/coldgraph.go`、`db/digest.go` |
| 对照版本 | `ce42b66a6b1f8150380f2cbdedcd98b34d4bd404d56869ada31a67f0671475c3` |
| 来源许可证 | ARTEX 根目录为 AGPL-3.0；本项目不直接复制 Go 实现 |
| 学习内容 | 图边方向、hot/cold 判定、连续冷却轮次、确定性分组、anchor、摘要签名、covers 和 supersede 生命周期 |
| SecMind 重写 | 以 Python 纯函数、现有黑板投影和独立持久化表实现；保留原始节点与证据，不改写事实内容 |

## ARTEX 设计中值得学习的部分

1. **因果图与派生视图分离。**真实探索边表达父节点到子节点的因果关系；`digest/covers` 只表达折叠视图，不能参与下一轮热度和分组计算。
2. **活动前沿优先保留。**`open`、`running`、`paused` 的 intent 本身、所有祖先，以及其直接子节点保持 hot。这样活动分支上下文不会因摘要而丢失。
3. **冷却采用 debounce。**节点第一次进入结构性 cold 时记录 `cold_since_round`，连续达到 `R` 轮才有资格折叠；重新活跃时清除时间戳。
4. **折叠范围保守。**目前只允许 settled `fact` 和 `intent` 作为成员；`finding`、`goal`、`hint`、`begin` 和 `digest` 保持可见，不直接折叠。
5. **分组可复现。**先按真实边连接冷节点，再把共享同一真实父节点的 singleton 冷叶子合并；父节点只是 anchor，不成为成员。
6. **摘要可缓存且可失效。**摘要签名同时包含 member/anchor 的稳定 ID 与 `content_version`。签名未变时复用已有摘要，变化时生成新摘要并 supersede 旧 digest。
7. **历史可追溯。**active digest 通过 `covers` 指向当前成员；旧 digest 保留为历史节点，但不再参与 active coverage。
8. **算法不依赖递归。**深链和环用迭代遍历，避免恶意或异常图导致栈溢出。

## SecMind 当前差距

| 能力 | 当前已有 | 仍缺什么 |
|---|---|---|
| 上下文压缩 | `ContextManager` 按预算选择上下文，保留 provenance，并将超预算内容写入 working summary | 没有图级 hot/cold 状态、冷却轮次、摘要成员版本和可恢复 covers 关系 |
| 黑板图 | `/api/v1/runs/{run_id}/blackboard-graph` 返回 facts/intents/hints，并由 `BlackboardGraph` 展示 | 节点 ID、kind、state、父子方向和内容版本尚未形成 M5 稳定契约；无 digest 节点投影 |
| 规划状态 | `dag.py` 和黑板协调器保存计划、依赖与运行结果 | 没有统一的 planner round 与 `cold_since_round`，也没有在分支重新激活时恢复原节点的规则 |
| 原始材料 | AgentState、账本和证据记录可读取 | 缺少“摘要成员 → 原节点 → 原始证据”的统一引用 API 和展开入口 |
| 持久化 | 任务状态可恢复，证据有内容地址存储 | 没有跨重启的 digest、成员、anchor、签名、active/superseded 状态表 |
| 模型调用 | 已有模型网关、预算和 MockTransport 验收方式 | 没有摘要生成专用请求、签名复用和摘要失败后的保守降级策略 |

## M5 数据契约

### 1. 节点标准化视图

冷摘要算法只接收以下不可变投影，不直接读取任意 UI 字段：

```text
GraphNode {
  node_id: stable string        # 在同一 run 内稳定，跨投影不改写
  kind: begin | intent | fact | finding | goal | hint | digest
  state: open | running | paused | completed | blocked | failed |
         exhausted | stopped | active | superseded
  content_version: integer     # 内容或决定性状态变化时递增
  source_refs: [string]        # 原始事件、证据、步骤或产物引用
}

GraphEdge {
  source: node_id               # 父节点/上游
  relation: yields | derived_from | spawns | supports | covers
  target: node_id               # 子节点/下游
}
```

`covers` 是派生视图边，永远从因果图输入中排除。旧任务缺少 `content_version` 时按 `1` 读取；不能从摘要文本反推原始版本。

### 2. 热冷判定

每个 planner round 只对一个 run 计算一次：

- live intent 为 `kind=intent` 且 `state ∈ {open,running,paused}`。
- live intent 自身、所有上游祖先和直接子节点为 hot。
- 只有 `kind ∈ {fact,intent}` 且已 settled、当前不在 hot 集合中的节点才是 structural cold candidate。
- `R` 是连续冷却轮数，默认 `6`；`cold_since_round` 在首次变冷的 round 写入，达到 `round - cold_since_round >= R` 才可折叠。
- 节点重新进入 hot 或不再满足 foldable 条件时清除 `cold_since_round`。
- `K` 是最小成员数，默认 `2`；不足 `K` 的块保持原节点可见。

### 3. 摘要块与签名

```text
DigestBlock {
  member_ids: sorted unique [node_id]
  anchor_ids: sorted unique [node_id]
  signature: sha256(canonical(member_ids, member_versions,
                              anchor_ids, anchor_versions))
  body: string
  source_refs: union(member.source_refs, anchor.source_refs)
  generation: integer
  status: active | superseded
}
```

- 成员是实际被折叠的冷节点；anchor 只作为上下文，不创建 `covers`。
- 成员必须来自同一 run，且不能包含 digest 节点。
- `member_ids`、`anchor_ids` 和版本按稳定顺序编码，签名计算必须确定性。
- 相同 active signature 直接复用摘要 body，不重复调用模型；模型失败时不创建“空摘要”，原节点保持可见。
- 任一成员或 anchor 的 `content_version` 变化会使签名失效；新的 digest supersede 旧 digest，并原子移除旧 active covers。

### 4. 原记录与重新激活

- 原节点和原证据永远保留；digest 只是一层可折叠投影。
- 展开 digest 时返回摘要正文、成员列表、anchor 列表、版本、生成时间和每个成员的原始引用。
- 任何新事件、计划重新激活或新子节点产生都以原节点 ID 写入；原成员不会被删除，也不会被 digest 节点替代。
- 重新进入 hot 的成员从 active coverage 中移除，相关 digest 失效或进入 superseded；恢复后的图仍可定位到原记录。

## 计划中的最小实现

### M5.1 契约与纯函数

实现 `hot_set`、`structural_cold`、`cold_since` debounce、确定性分组和 `block_signature`。先用内存节点/边夹具验证深链、环、共享父节点和多分支场景。

### M5.2 持久化与恢复

新增独立迁移，至少保存：`run_id`、`round_no`、节点冷却时间戳、digest 元数据、成员关系、anchor 关系、签名、generation、active/superseded 状态和创建时间。写入 digest 与 covers 必须同一事务；恢复时校验 run 隔离和稳定 ID。

### M5.3 运行时接入

在规划唤醒成功后推进 round，计算并持久化 stamp；只有满足 `R/K` 的块才调用摘要生成器。复用现有模型预算和 MockTransport；生成失败保留原节点并记录可重试原因。

### M5.4 查询与工作台

扩展黑板图返回 digest 节点、`covers` 展开信息和原始引用。工作台支持折叠、展开、跳到成员原节点，以及显示摘要版本和失效原因；旧任务没有 digest 字段时继续按现有图渲染。

### M5.5 故障验收与操作说明

覆盖重复唤醒、签名复用、成员内容变化、anchor 变化、分支重新激活、迟到摘要回调、摘要模型失败、服务重启、深链/环、跨 run 引用和删除/缺失原证据。补充运行参数、迁移、回滚和排障说明。

## 暂不移植

- 不复制 ARTEX 的 Go 包、数据库封装或 UI 文件。
- 不把 `working_summary` 当作 digest 表；它缺少成员版本、失效和原记录展开能力。
- 不让 finding/goal/hint/begin 直接成为摘要成员；如果后续业务需要，先新增独立契约和回归。
- 不使用 digest/covers 边参与规划依赖、因果追踪或权限判断。
- 不在摘要生成失败时删除原节点或自动把失败结果当作事实。

## 完成判据

M5 只有在以下条件全部满足后才标记完成：

1. 纯函数测试证明 hot/cold、R 轮 debounce、分组、签名和环/深链行为稳定。
2. 迁移后重启能恢复 round、冷却戳、active digest 与 covers；重复迁移和重复 compaction 幂等。
3. 成员或 anchor 内容变化会生成新 digest，旧 digest 保留历史但不再覆盖；签名不变时不调用模型。
4. 工作台可展开摘要并定位每个原节点和证据，重新激活后原节点重新可见。
5. 运行时、API、前端测试、构建、`git diff --check` 和操作说明全部通过。

