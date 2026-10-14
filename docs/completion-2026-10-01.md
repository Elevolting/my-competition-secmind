# SecMind 完善与验收记录

日期：2026-10-01（Asia/Shanghai）
目录：`D:\tzb\SecMind\security-agent-suite-clean-20260904(2)`

本次围绕“提交任务 → 分析 → 审批 → 中断恢复 → 证据与报告”补齐可运行流程。以下测试结论对应本机本次执行，不引用历史 README 的发布分数。

## 项目结构与执行分工

| 组件 | 位置 | 运行职责 |
| --- | --- | --- |
| 统一平台 | an/src/security_agent | 任务入口、路由、预算、审批、SQL 状态、事件账本、经验库、报告 |
| Web 工作台 | an/frontend | React/Ant Design 页面、真实事件流、结果与操作入口 |
| SecMind 引擎 | secmind/src/secmind | 独立证据分析与准入内核；代码包版本 0.8.7，公共 Schema 1.7 |
| Security Runtime | security-runtime/security-runtime | 渗透项目、事实与意图黑板、Dispatcher 和 CLI Worker |

前端 5173 → 统一 API 8001 → SecMind 8002 或 Security Runtime 8000。Dispatcher 没有监听端口。

## 本次完成的功能

### 1. 任务恢复与预算

- SQL 快照保存下一执行节点、活动节点与执行时间。
- 排队任务可以恢复；完成的工具步骤不会因为重启而重放。
- 外部任务已返回 ID 时继续查询原任务。提交时中断、没有回执的非幂等操作转为部分报告，提示人工核对，不自动重复提交。
- 审批保存到数据库；修改参数后重新做 Schema 和安全策略检查。相同任务的重复审批受到锁和在途去重保护。
- 实际 Provider 请求（包括失败重试）计入调用预算；步骤、工具次数和运行时间耗尽时保存 partial 报告。
- 时间预算到期时尝试取消已有 SecMind 任务或停止 Runtime 项目；取消失败会单独记录。
- 部分完成、降级、证据校验失败不会被 Reporter 升格为 completed。

主要实现：`orchestrator.py`、`service.py`、`schemas.py`、`agents.py`；回归：`an/tests/test_runtime_completion.py`。

### 2. SecMind 代码审计、逆向和日志分析接入

- 新建单任务支持 `analysis_backend=auto|local|secmind`。auto 在统一平台演示模式使用本地扫描，在线模式使用 SecMind；此选择仅用于代码审计。
- 代码审计、逆向、日志分别提交到 `code_audit_and_patch`、`forensics_static_reverse`、`logs_ir_hunting` 领域。
- 传输所有边界内材料并保留相对路径，避免仅取前 50 个文件或同名文件相互覆盖；超限明确报错。
- 外部任务 ID 和状态即时落盘；重启、审批完成后的轮询不再创建第二个任务。
- 独立引擎的审批显示在统一任务中；响应按引擎契约提交，并携带稳定 resolution_id。审批 HTTP 失败保留原请求，允许重试。
- 完整引擎不可用时，已有本地扫描/格式识别证据仍可保存，但状态是明确的降级 partial。
- 可配置 `SECURITY_AGENT_SECMIND_OPERATOR_TOKEN`，仅用于独立引擎认证，不回显到任务或配置页面。
- 远程报告身份与任务 ID 必须匹配，不能把其他任务的报告混入当前任务。

主要实现：`secmind_adapter.py`、`tools.py`、`fusion.py`；回归：`an/tests/test_secmind_bridge.py`。

### 3. 报告刷新与真实页面状态

- 刷新报告读取已有外部任务，不重复上传、创建任务或调用模型。
- 渗透完成要求项目进入成功终态且目标意图已完成。单独出现 Flag 文本不足以将整个任务标为 completed。
- 刷新生成的渗透发现关联实际 Evidence，不再无依据地写入“命令注入修复”。
- 流程图依据对应的工具、验证和报告事件显示进度；大量模型流事件不会自动点亮未执行步骤。
- 渗透流程依据项目、意图、执行器分配、非种子事实与目标完成证据显示。
- 日志分析加入新建任务路由、模块状态、工作台和经验库标签。
- 模型页面明确：统一平台、SecMind 和 Dispatcher 的配置与用量分别管理。
- 新建任务弹窗限制表单区域高度，提交按钮保持在视口内。

主要实现：`report_sync.py`、`api.py`、`TaskModal.jsx`、`moduleFlowModel.js`、`ModuleFlow.jsx`、`ModelUsagePage.jsx`。

### 4. Windows 执行与生命周期

- Windows 取消 Worker 时先终止进程树，避免父进程先退出而遗留子进程。
- 本地 mock worker 使用当前 Python；容器 mock 保持容器解释器约定。
- 同一 Dispatcher 配置使用 OS 文件锁，阻止两个进程竞争同一任务。
- 启停脚本用套件路径、组件命令、进程创建时间识别归属，穿过 cmd/uv/Python 中间启动器正确分组。
- 启停操作互斥；支持 `-Only`，停止支持 `-WhatIf`。不会按固定端口清理无关程序。
- 使用 `_runtime/services.json` 保存进程状态，日志带启动时间戳；健康检查失败返回失败状态。
- 已清理两个重复 Dispatcher 进程组，并重启更新后的统一 API 与单个 Dispatcher。其他服务保持运行。
- 重复执行启动命令确认 API、Dispatcher 各保持一个进程组；原有主机监测已恢复。

主要实现：`local_process.py`、`instance_lock.py`、`start-all.ps1`、`stop-all.ps1`、`scripts/suite-processes.ps1`。

## 本次验收结果

| 验证范围 | 结果 |
| --- | --- |
| 统一后端全部现有与新增测试 | 125 passed |
| Security Runtime 全部测试 | 106 passed；此前 Windows 失败项已修复 |
| SecMind 选定的 API、恢复安全、领域契约测试 | 83 passed；并非全引擎测试集 |
| 前端 Node 测试 | 17 passed |
| 前端生产构建 | 成功；仍有依赖指令、空 React chunk 和大 bundle 提示 |
| 隔离的真实跨服务代码审计 | completed；2 个发现、5 条证据 |
| 隔离的真实跨服务日志分析 | completed；1 个发现、4 条证据 |
| 浏览器冒烟与截图检查 | Edge headless；引擎选择、弹窗提交区、模型范围提示正常；无未捕获页面异常 |
| 生命周期 | PowerShell 7 与 Windows PowerShell 5.1 检查通过；归属/分组/语法检查与 -WhatIf 演练通过 |
| 当前服务健康 | 5173、8000、8001、8002 均 HTTP 200 |

合计 331 项自动化测试通过，另有两条真实跨服务离线验收。离线验收显式禁止 live models，Provider 行为使用受控 MockTransport 验证；没有通过新增付费模型调用来验证质量。

跨服务验收启动了临时 SecMind 服务，使用独立临时目录、SQLite 和上传材料，显式设置 offline/禁止 live models。统一平台使用实际 HTTP 与该引擎通信，验证上传、任务结果、证据、账本哈希链与报告刷新。没有用生产数据库制造测试任务。

复测跨服务流程：

```powershell
# 在套件根目录，使用已有虚拟环境
.\an\.venv\Scripts\python.exe -B .\scripts\verify-completion.py

# 不终止真实进程的生命周期测试
.\scripts\test-lifecycle.ps1
.\stop-all.ps1 -Only an-api,dispatcher -WhatIf

# 前端测试
Set-Location .\an\frontend
npm test
```

浏览器复测脚本为 `scripts/verify-ui.cjs`，需要 Playwright 与已安装的 Edge。它仅读取页面、操作未提交的表单，不创建真实任务。可将 Playwright 模块路径作为首个命令行参数。

## 数据保留与备份

修改前创建并校验了：
`D:\tzb\backups\SecMind-before-completion-20261001-155453.zip`

备份约 21.6 MB，包含 1,469 个源码/配置/文档文件以及 6 个 SQLite 一致性快照、SHA-256 清单。依赖目录、完整上传样本、运行材料及日志不在此源码备份内。备份含私有本地配置，应作为私有文件保存。

已有 37 个统一平台任务记录保留；未通过批量重写历史结果来制造完成率。没有 Git 元数据，因此本次没有生成提交或声称存在可用 Git 回滚点。

## 仍然存在的实际边界

1. 当前仍是本机开发部署：SQLite、开发模式工具、未配置 sandbox runner；这次验收不能代替生产隔离与认证验收。
2. SecMind 就绪接口仍报告 Semgrep、Gitleaks、Syft、OSV 不可用。内置分析可以执行，但不等于上述外部工具已安装或覆盖完整。
3. 三个执行组件的模型设置与用量独立。统一平台页面不汇总独立引擎的真实消耗，也不会替用户修改这些密钥配置。
4. MCP 调用仍是操作人触发的可审计功能；未把工具目录包装成“所有工具都会被 Agent 自动使用”。
5. 未执行完整 SecMind 发布测试、PostgreSQL/Qdrant/容器测试或付费在线模型质量评测；不沿用旧文档中的覆盖率和 benchmark 分数宣称本机达到同等结果。
6. 外部 POST 已接受但回执丢失时，没有安全依据自动重建任务。当前保留不确定状态与报告，需核对外部记录；有 ID 的正常恢复流程已验证。
7. 仅重启 API 会停止操作人开启的主机监测。此次已恢复原来的开启状态，日后单独重启后需按需要重新开启。
