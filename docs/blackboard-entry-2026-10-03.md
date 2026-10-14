# 所有任务通过黑板组织工具执行

所有统一工作台任务都先绑定黑板项目和当前步骤意图，再由受控 Worker/工具执行。渗透任务仍使用 `penetration_module` 将任务交给 Security Runtime Dispatcher；代码审计、逆向、日志分析和普通 MCP 任务也使用同一套项目、意图、Worker 租约、事实回写和终态封存流程。演示/离线模式使用随任务 Ledger 持久化的本地黑板图，保持相同的入口与状态机约束。

普通任务的远程项目设置 `dispatcher_enabled: false`，由统一工作台执行已分配意图；渗透项目保留 Dispatcher 自动调度。Security Runtime 会把旧版统一工作台项目在数据库迁移时标为外部执行，避免 reason Worker 误接管。普通项目的黑板身份校验也要求这个标记保持关闭。

## 执行与回执

1. 主规划器只生成受限工具步骤；每个步骤在执行前由黑板协调器创建或恢复项目与意图。渗透任务不再挑选直接 MCP 工具，模型返回的直接或混合工具计划会被归一化为黑板提交。
2. 计划校验、审批前检查与执行入口均拒绝绕过黑板的计划。旧任务恢复遇到此类计划会停止并提示重试，不会自动重放旧工具调用。
3. 本机 Claude Worker 通过 `security_agent.blackboard_mcp_server` 连接工作台。Dispatcher 为每次执行生成独立 MCP 配置，绑定项目、意图和 Worker；reason / conclude 阶段没有此工具连接。
4. 工作台每次调用核对运行状态、黑板项目状态及意图分配，并检查工具连接和协议版本。停止、完成、已收束或改派的意图不能发起后续工具调用。
5. MCP 回执写入工作台的 `mcp-runtime.db` 和任务 Ledger，并带有 `blackboard.project_id`、`intent_id`、`worker`。Worker 工作目录的 `.mcp-results` 保存完整回执；Worker 在结论事实中引用这些文件。
6. 工具成功只表示该次工具返回成功，任务完成仍由黑板终态及目标意图证据决定。黑板不可用时不转为主规划器直接执行工具；普通内置模块也会因无法创建/恢复黑板意图而停止。
7. 黑板 MCP 工具调用在发送 `tools/call` 前原子占用额度，默认每个任务 60 次、每个意图 20 次；额度持久化，失败或结果未知的调用也计入。可用 `SECURITY_AGENT_BLACKBOARD_MAX_MCP_CALLS_PER_RUN` 和 `SECURITY_AGENT_BLACKBOARD_MAX_MCP_CALLS_PER_INTENT` 调整。工作台内置的本机 MCP 文件工具只允许访问与当前任务 ID 绑定的工作区；已知 URL/target 参数由统一范围校验绑定到任务授权范围，非标准参数仍需逐服务审查。

## 本机配置

当前 `security-runtime/dispatch.local.yaml` 的本机 Claude Worker 已配置：

```yaml
mcp_bridge_python: "../an/.venv/Scripts/python.exe"
workbench_url: "http://127.0.0.1:8001"
```

路径相对于调度配置文件解析；Python 环境需安装工作台包。桥接复用工作台已启用、成功发现的 MCP 服务及调用回执。此桥接目前支持本机 Claude Worker；容器和其他 CLI Worker 尚未接入。

历史任务及其图数据不补造、不自动重跑。恢复中的新步骤会检查并恢复已持久化的黑板绑定；旧任务没有可确定绑定时停止并要求重试。步骤已有成功或结果未知的黑板事实时拒绝重放；明确失败的受控重试和远程审批续跑会从前一事实创建新意图。需要使用新流程时，从界面重试对应任务。

## 验证

新增测试覆盖模型绕过尝试、混合计划、旧计划恢复、服务不可用、Worker 配置与阶段限制、意图改派/停止/收束、协议漂移、真实 stdio Base64 工具的成功和失败，以及回执与 Ledger 关联。未重新对历史靶场发起扫描。
