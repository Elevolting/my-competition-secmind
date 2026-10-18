# 旁路问答操作说明

本文说明 SecMind 旁路问答的入口、状态和故障边界。旁路问答使用提交时保存的模型请求快照，拥有独立的请求、预算、取消和历史记录；它不会改变主任务的状态机。

## 入口

工作台任务详情页在存在模型请求快照时显示旁路问答面板。面板可以创建问题、轮询当前状态、查看历史回答、查看快照时间、取消请求和清除当前回答。关闭或刷新页面只停止前端轮询，服务端请求继续执行；重新打开页面会从历史接口恢复记录。

两套服务都提供同样的 `/api/v1` 路径：

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `/runs/{run_id}/side-questions` | 依据 `snapshot_id` 创建旁路问题 |
| `GET` | `/runs/{run_id}/side-questions` | 查询该任务的历史问题 |
| `GET` | `/runs/{run_id}/side-questions/{question_id}` | 查询状态、回答、快照和用量 |
| `GET` | `/runs/{run_id}/side-questions/{question_id}/events` | 按输出序号读取累计输出事件 |
| `POST` | `/runs/{run_id}/side-questions/{question_id}/cancel` | 请求取消单个旁路问题 |
| `POST` | `/runs/{run_id}/side-questions/{question_id}/clear` | 清除当前回答并建立迟到输出 fencing |

工作台服务的实现位于 `an/src/security_agent/side_questions_api.py`，独立引擎位于 `secmind/src/secmind/api_side_questions.py`。两个实现共用同一套领域契约，但分别使用各自的数据库和运行时资源。

## 创建和快照

创建请求至少包含 `question`；不提供 `snapshot_id` 时使用该任务最新的工作台快照。可以提供稳定的 `request_key` 和输入 token 估算：

```json
{
  "snapshot_id": "snapshot-uuid",
  "request_key": "why-this-finding",
  "question": "这个结论依据哪一次请求？",
  "estimated_input_tokens": 256
}
```

快照必须属于同一个 `run_id` 和服务来源，并且保存了发送给模型的真实请求边界、模型配置身份、版本和 `captured_at`。回答页面展示的是该冻结上下文的时间和来源，不从当前页面活动日志拼接上下文。找不到快照、快照跨任务或来源不匹配时返回 `409`；模型配置身份已变化时也返回 `409`，需要主任务重新产生快照。

## 状态和用量

状态流转为 `queued` → `running` → `completed`、`failed` 或 `cancelled`。服务启动时数据库中残留的 `running` 会变为 `interrupted`，保留已经写入的累计回答和用量，不会自动重新调用模型。

每个父任务单独计算旁路输入和输出预算，并限制活动请求数。工作台默认输入预算为 256000 token、输出预算为 8192 token。创建时根据快照的 UTF-8 大小估算输入额度，至少预留客户端提供的估算值；输出只预留当前剩余额度，并作为模型调用的输出上限。模型返回后按服务商报告的实际用量结算；预算不足或并发达到上限返回 `409`。快照过大时可在模型调用前得到预算错误。

旁路模型请求采用流式接口，兼容只对流式调用返回回答的模型网关。冻结的模型请求只作为问答参考资料，原请求的 JSON 报告格式不用于旁路回答。生成中的回答按增量保存，页面轮询显示当前文本与流式光标；刷新后可从历史和输出事件恢复。模型调用失败时，历史记录包含稳定错误类型和可阅读的中文提示，不包含上游响应正文或密钥；页面会展示该提示。列表请求短暂失败时，页面显示加载错误并继续尝试连接。

`request_key` 是幂等键。同一父任务、快照和问题重复提交会返回已有记录，不会重复调用模型；同一个 key 搭配不同问题、快照或父任务返回 `409`。客户端应在重试时复用原 key。

## 取消、清除和迟到输出

取消只标记目标旁路问题，主任务继续运行。模型调用已经进入进行态时，服务端会丢弃取消之后到达的回答，并将问题结算为 `cancelled`。清除操作只清除当前可见回答，同时递增 `clear_version`；旧版本的迟到输出会被拒绝，新的回答必须使用新的 fencing 版本。

输出事件带单调递增的 `sequence`，客户端可用 `after_sequence` 增量读取。回答字段保存当前累计文本，重连时应先读取问题快照，再按序号补事件或直接使用历史回答。

## 刷新、断开和重启

- 页面关闭、浏览器刷新或网络断开不会自动调用 `cancel`。
- 页面恢复后调用历史接口即可找回已提交问题和终态；`captured_at` 用于说明回答依据的上下文时间。
- API 进程重启会把未完成的 `running` 标记为 `interrupted`，不会重放模型请求，也不会把它误报为 `completed`。
- 已保存的回答、输出事件和实际用量保留在数据库中；重启恢复不影响主任务状态。

## 本地验收

验收使用临时数据库、FastAPI `TestClient`、Mock 回调和固定快照，不调用真实付费模型：

```powershell
cd D:\tzb\SecMind\security-agent-suite-clean-20260904(2)\an
.\.venv\Scripts\python.exe -m pytest -q tests/test_side_questions.py tests/test_side_questions_api.py

cd ..\secmind
.\.venv\Scripts\python.exe -m pytest -q tests/test_side_questions.py tests/test_side_questions_api.py tests/test_model_snapshots.py tests/test_migrations.py tests/test_migration_guard.py

cd ..\an\frontend
npm test
npm run build
```

故障矩阵覆盖无快照、跨父任务／来源、配置变化、重复 key 冲突、输入预算不足、并发上限、独立取消、清除后的迟到输出、服务刷新后的历史恢复，以及主任务保持运行。迁移测试确认独立引擎启动时仍位于 migration head。

## ARTEX 学习来源和重写边界

本功能学习 ARTEX 的 `sidequestion/README.md`、`sidequestion/context.go` 和 `server/side_questions.go` 中的快照、独立生命周期、历史和用量设计；SecMind 使用 Python、FastAPI、React 和现有模型网关重写行为契约，没有直接复制 ARTEX 源码。ARTEX 根目录许可证为 AGPL-3.0；任何未来的逐文件代码移植都必须记录来源版本、版权、修改点和许可证，不能仅依据 `web/LICENSE` 判断整个仓库的许可证。
