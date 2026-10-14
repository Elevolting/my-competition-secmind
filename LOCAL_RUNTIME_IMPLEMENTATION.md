# 本机真实执行功能交付记录

日期：2026-09-30。用户确认本轮先完整打通当前部署机器的采集与处置。

## 备份

修改前完整备份：`D:\tzb\backups\SecMind-before-runtime-20260930-155808.zip`。
归档 39,211 个文件，215,820,497 字节，包含配置、数据库、源码和依赖。SQLite 使用在线快照，文件哈希写入 `BACKUP-MANIFEST.json`，ZIP CRC 校验通过。

恢复时先停止本项目服务，保留当前目录，将备份解压到独立目录并核对清单后再启动。不要将旧数据库或部分旧源码直接覆盖到正在运行的新版本中。

## 现在可以实际操作的功能

### 本机采集与驾驶舱

访问 `http://127.0.0.1:5173/incident-response`，点击“启动采集”。

- 使用 psutil 读取实际进程、TCP 监听端口、网卡、内存、磁盘和开机时间，周期为 15 秒。
- “刷新资产基线”保存当前完整采集；后续采集列出相对基线新增的监听地址/端口。
- “采集 Windows 登录失败日志”读取 Security 日志中的 4625 事件：近 24 小时、最新 200 条，按需执行。权限不足会保留失败回执；只有查询成功且确实无记录时才显示空列表。
- 驾驶舱直接显示本机采集结果，包括进程数、监听端口、全接口监听数、采集时间和模块状态。全接口监听不代表网络可达、漏洞或攻击，不用于伪造风险评分。
- 监控启动由操作人控制；API 重启会保留快照和基线，但需重新点击启动采集。

### 取证、隔离、恢复与防火墙

- “保存本机取证快照”写出实际 JSON 文件，回执含 SHA-256、文件大小和证据 ID，页面可下载核验。
- “隔离上传的文件”：上传保存样本 → 提交审批 → 审批前保持原文件 → 批准后校验哈希、复制到隔离目录、核验副本、移除原路径。不会运行样本内容。
- “恢复已隔离文件”：选择隔离 ID → 提交审批 → 批准后按原路径恢复并核对哈希。原路径已有文件时拒绝覆盖。保留隔离副本和清单供审计。
- 文件操作限定于应用的上传目录、输入目录和本模块样本目录；不提供任意路径删除或任意 shell 执行接口。审批后文件内容变化会失败并要求重新提交。
- Windows 防火墙执行器通过 `netsh` 创建指定远端 IP 的出站阻断规则；撤销时仅删除本平台创建的精确规则名。需要 API 进程具备相应权限，失败不会显示为成功。
- 审批、日志、执行状态和回执持久化到 SQLite。并发重复审批只执行一次。服务中断期间没有完成回执的动作标为中断待核对，不自动重复执行。

文件隔离是受控文件保全操作，不等同于停止已运行进程或完整 EDR 隔离。验证未对真实网络创建防火墙阻断规则。

### MCP 协议连接与执行

访问 `http://127.0.0.1:5173/mcp`，在“SecMind 本机分析”点击“连接并发现工具”。

支持官方 MCP SDK 的 stdio、Streamable HTTP 和 SSE；实际 initialize 和 tools/list 成功后才显示发现结果。每次调用重新建立会话，校验服务端参数 Schema，执行 tools/call，并保存成功或失败回执。

随项目提供的本机 MCP Server 有四个实际工具：

| 工具 | 实际行为 |
| --- | --- |
| `hash_file` | 对授权目录内文件计算 SHA-256 和大小 |
| `inspect_python` | 解析 Python AST，列出函数与导入，不运行源码 |
| `audit_python` | 运行已安装的 Bandit 静态扫描，返回规则、位置、发现与错误 |
| `decode_base64` | 严格解码 Base64，返回文本、长度和哈希 |

第三方 MCP Server 需提供真实可执行程序/参数或已运行的服务地址，并显式启用。目录中的 Semgrep、CyberChef 等旧条目不会自动部署这些软件。参数填写 JSON，点击实际调用并确认；可选填已有任务 ID，将回执写入该任务的审计账本。

本轮 MCP 入口由操作人调用，不会把第三方工具自动交给模型自主选择执行。工具发现/调用有超时，重启后缺少终态回执的调用标为中断。

### 真正生效的 Prompt

访问 `http://127.0.0.1:5173/prompts`。统一 API 的分类、规划、工具方案、证据分析、报告五个阶段已接入 `ModelGateway`。

- 编辑并保存后，后续模型调用读取新版本；原有调用协议与约束保留。
- 保存采用版本哈希校验，防止过期页面覆盖更新；历史版本可填回编辑器后再次保存。
- 调用事件 `llm.prompt.selected` 记录模板版本、内容哈希及实际拼接指令哈希。
- 六份旧工具协议模板保留为只读参考，未冒充已接入。此页面不覆盖独立 SecMind/渗透 Worker 各自的提示词。

## 数据与代码位置

默认数据位于 `an/data`，跟随 `run_root` 的父目录：

- `incident/operations.db`：应急状态、审批、历史事件。
- `incident/evidence`：证据 JSON；`incident/samples`：上传样本；`incident/quarantine`：隔离副本及清单。
- `mcp-runtime.db`：MCP 探测与调用回执；`mcp-catalog.json`：连接配置。
- `runtime-prompts.db`：当前 Prompt 与历史版本。

新增模块在 `an/src/security_agent`：`operations.py`（持久化）、`host_collector.py`（采集）、`operations_api.py`（操作 API）、`mcp_runtime.py`（协议客户端）、`local_mcp.py`（本机 Server）、`runtime_prompts.py`（运行 Prompt）。`incident_response.py` 已替换原来的模拟执行逻辑。

## 验收与限制

- 后端 43 项相关测试通过：API、Ledger、模型网关、任务智能体、编排器、目录、本机处置及 MCP。
- 前端 13 项测试及生产构建通过。仍有现有依赖警告和包体大小提醒。
- 真实 MCP 子进程完成握手、文件哈希、AST、Base64 调用；Bandit 验证用静态测试源码检查 B602 规则。
- 浏览器完成启动采集、生成/下载证据并核对 SHA-256、上传无害文件、提交/批准隔离、恢复并逐字节核对、MCP 真实调用、Prompt 页面与驾驶舱展示。
- 已实际重启统一 API，核对处置记录、隔离/恢复清单和 MCP 回执仍然存在，随后重新启动采集。
- Windows Security 日志在本机读取成功，验收时近 24 小时登录失败记录为 0。
- 防火墙测试验证参数、审批和权限失败处理；没有实际阻断本机网络。模型 Prompt 注入用受控 HTTP 测试校验实际请求体，没有额外调用付费模型进行验收。

主要测试命令（在 `an` 目录）：

```powershell
uv run --extra dev pytest -q tests/test_local_operations.py tests/test_real_dashboard.py tests/test_api.py tests/test_llm.py tests/test_ledger.py tests/test_agents.py tests/test_orchestrator.py tests/test_catalogs.py
```

浏览器回归脚本：`_runtime/verify-local-runtime.cjs`，依赖当前本机 Chrome/Playwright 路径。该脚本会通过正在运行的 API 保存无害样本、证据、审批记录和 MCP 回执，属于真实验收数据，不会修改防火墙。

截图：`_runtime/local-response.png`、`_runtime/mcp-execution.png`、`_runtime/cockpit-local-host.png`。
