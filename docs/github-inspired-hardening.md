# GitHub 参考模式与本地落地

本轮只读取公开 GitHub README，未调用或探测任何外部目标。参考项目提供的是数据和运行时设计模式，不是直接复制代码。

## 参考项目

- [TheHive](https://github.com/TheHive-Project/TheHive)：把调查组织为 case、task、observable、work log 和 evidence，并保留多人协作的实时审计线索。
- [Velociraptor](https://github.com/Velocidex/velociraptor)：以本机 artifact collection 为边界，强调可复核的主机采集结果和本地 triage。
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti)：用实体关系图管理 observables，并为信息保留来源、置信度、时间和原始报告关联。
- [LangGraph](https://github.com/langchain-ai/langgraph)：长时状态工作流需要 durable execution、checkpoint、human-in-the-loop 和可恢复内存。

## 已落地

### 黑板与工具调用

- 黑板项目、意图、Worker、租约和结论事实仍是调用门禁。
- MCP 黑板调用新增可选 `request_id`。同一任务/意图重复提交同一键时，SQLite 返回原始回执，不重复执行工具，也不重复占用预算。
- 请求键与 `call:*` 回执在同一事务中登记；服务重启会把未确认调用标记为 `interrupted`，不会自动重放。
- 网络 MCP 的 target/url 检查递归覆盖嵌套参数，避免把 `request.url` 或数组对象当成非网络参数。

### 资产引用图

- 节点和关系现在携带 `provenance`：来源、回执/范围引用、置信度和观察时间。
- 只有成功工具回执中的显式 `coverage` 才能产生 discovered 节点；授权范围、输入材料和工具观测继续分层显示。
- 图统计新增 scoped/discovered/relationship/coverage observation 数量，仍不把引用数量冒充扫描覆盖率。

### 应急响应证据

- 取证下载接口会重新计算文件 SHA-256，并与执行回执比对；不一致时拒绝下载并返回 409。
- 既有的审批、隔离目录限制、文件哈希和本机范围约束继续生效。

## 验证边界

所有回归只使用 `127.0.0.1`、本地 workspace 和本地 Security Runtime。公开 GitHub 仅用于阅读项目说明，未对第三方站点执行扫描、渗透或工具调用。
