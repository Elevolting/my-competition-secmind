# M5 冷节点摘要操作说明

## 当前范围

M5 把黑板的长期历史转换成可折叠的摘要投影。原始节点、证据和账本事件始终保留；摘要不能作为规划依赖、权限判断或新的事实使用。当前默认 `R=6`、`K=2`：节点连续满足冷却条件 6 个 planner round，且一个块至少有 2 个成员后才可折叠。

## API

读取某个任务的摘要状态：

```http
GET /api/v1/runs/{run_id}/cold-digest
```

手动推进一次 compact round：

```http
POST /api/v1/runs/{run_id}/cold-digest/compact
Content-Type: application/json

{"R": 6, "K": 2}
```

请求会校验任务绑定的黑板项目 ID 和标题。返回值包含 `round_no`、节点冷却戳、摘要正文、签名、generation、成员/锚点版本、来源引用和 `active`/`superseded` 历史。

## 判定规则

- `open`、`running`、`paused` 的 intent 及其祖先和直接子节点保持 hot。
- 只有 settled 的 `fact`、`intent` 可以成为候选；`finding`、`goal`、`hint`、`begin` 和 `digest` 不直接折叠。
- `covers` 是派生视图边，不参与热度、因果和分组计算。
- 相同成员、锚点和版本签名复用 active 摘要；成员或锚点内容改变会创建新摘要并让旧摘要进入 `superseded`。
- 摘要生成失败或结果为空时保留原节点，并记录可重试的失败原因；不得创建空摘要替换原始记录。

## 工作台行为

黑板图会显示“冷节点摘要”节点。默认隐藏 active digest 覆盖的成员；展开摘要或从搜索结果进入时，成员原节点重新显示。详情面板列出正文、签名、代数、成员、锚点和来源引用，点击成员可定位原节点并继续查看证据。

## 重启与排障

round、冷却戳、摘要历史和 active covers 存在 SecMind 数据库中；服务重启后通过 `GET` 可恢复。若摘要不可用，先确认任务已绑定黑板项目，再检查项目 ID/标题是否匹配，随后查看账本事件 `blackboard.cold_digest.compacted` 和 `cold_digest` 快照。重新激活的分支应先让原节点恢复可见，再由下一次 compact 更新摘要覆盖。

## 当前限制

本阶段的手动 compact 接口和确定性文本摘要已接入，真实 planner round、模型摘要生成、上下文 token 节省对照和正式迁移仍在 M5.3–M5.5 验收范围内。自动化测试使用固定图、临时数据库和 MockTransport，不调用真实付费模型。

