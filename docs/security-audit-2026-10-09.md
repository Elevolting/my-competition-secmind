# SecMind 安全审计记录（2026-10-09）

## 自有代码覆盖

- 任务 URL 输入、重复拼接、畸形方案、上传 `.url` 材料和路径范围。
- MCP 发现、目标范围、工作区文件、黑板项目/意图租约、连接与工具版本、预算、幂等回执、任务取消/恢复。
- MCP 审批前不调用；批准绑定同一任务、意图、工具版本、参数摘要的一次请求；参数改变、重复请求、拒绝、租约过期和任务结束均拒绝。
- Pi 与 Claude 黑板桥接轮询同一审批记录；R3 和不可可靠限定目标的工具拒绝。
- 渗透事实归类：工具拒绝、目标不可达、未确认事实不会生成漏洞节点。
- 修复 ToolBroker 按 `mcp:` 名称前缀读取 MCP 专有字段的问题；审批判断现在基于实际 MCP 工具类型。管理 API 对非纯工具和任务关联直调均返回 403。

## 内置工具接入核对

| 工具 | 来源/版本 | 当前 SHA-256 | 签名/连接 | 覆盖范围 |
|---|---|---|---|---|
| Burp Community | PortSwigger 官方下载，2026.3.3 | `46b60895b2488bc76911795c53a85ae2ef2f5d6ff734b6ec6f5dd616b2b99875` | JAR ZIP CRC 已校验；Windows Authenticode 不适用 | MCP 扩展配置与本机 SSE；未审计 Burp/扩展内部源码 |
| Burp MCP 扩展 | 项目内置 `burp-mcp-all.jar` 1.3.0 | `c4011245ee7da0cb901b9c0435aba3d8458ab5b0e2078e1a87fd025ed93c7892` | 本机 `127.0.0.1:9876` 完成 SSE 握手，发现 24 个工具 | 监听配置和接入边界；未审计扩展内部源码 |
| Yakit/Yak | 项目内置 Yak 引擎 1.4.9-beta1 | `2860e5fc4fb1e452d576d8cbf0964b17d17c2dc8b8a1cafab4bcfb5b1772c3d6` | Authenticode `Valid` | MCP 协议、工具目标/参数边界；无引擎源码审计 |
| TscanPlus | TideSec 官方 GitHub `v3.5.3` 发布包，SHA-256 `cab88d3430bfd077abc4af62b4973d444042ac973e8737cebc86ea54edc07f0d` | EXE `5ad39426f5486d5adeba834066b425915f01f825124ddb79613b005a55c22571` | Authenticode 仍为 `HashMismatch`；仅固定官方 EXE 摘要可通过接入门槛 | 官方发布元数据、归档摘要、签名异常；无二进制源码审计 |
| Reqable | 项目内置 3.2.23 | `43dc8671384614ea83faed03c4ed83b9b8981932306c3928fedffe54d46d6228` | Authenticode `Valid` | MCP 配置、9001 端口边界；无桌面程序源码审计 |

## 监听与运行状态

- SecMind API：`127.0.0.1:8001`；前端：`127.0.0.1:5173`。
- API 目录当前显示 159 个可发现工具；TscanPlus `connected`（25 个），Burp `connected`（24 个）。此计数只涵盖当前连接成功的服务。
- Burp 扩展实际监听 `127.0.0.1:9876`，项目注册脚本已同步为该地址。Burp 首次启动需完成临时项目向导；启动脚本现在显示其窗口。
- TscanPlus `jwt_decode` 实际调用成功，回执 `57ba86c9-d00e-489d-b926-286ff70991fc`；Burp `base64_encode` 经 SecMind API 返回 `U2VjTWluZCBCdXJwIGNvbm5lY3RlZA==`，回执 `ed3b65d4-08fe-4723-95f3-c0370f67fc65`。
- 旧 Docker Claude Dispatcher 的凭据在健康检查中返回 HTTP 402 `Insufficient Balance`。该可选容器已停止；默认本机 Pi Dispatcher 仍在运行。
- 当前 Pi 模型代理在 `stream:false` 请求中可能返回只有用量、没有正文的 SSE；`stream:true` 实测返回模型正文。模型网关已兼容 SSE 完成响应，页面连接测试改为流式请求并实测成功。旧 Claude 凭据的余额并未改变。

## 回归验证

- SecMind 后端全量测试通过；MCP 审批、黑板租约/预算/取消及任务重试专项测试通过；Security Runtime 146 项通过。
- 前端 26 项测试及 Vite 构建通过；管理页不再提供无效的任务 ID 关联入口。
- 真实新任务的只读与逐次审批验收尚未完成；默认 Pi 模型连接测试已成功，仍需用新的授权任务核对完整流程。历史运行记录未改写。
