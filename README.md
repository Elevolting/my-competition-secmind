# SecMind 本地安全任务套件

本目录是 Windows 本机单用户套件：React 工作台统一创建与查看任务，`an` 负责规划、预算、审批、证据和报告；Security Runtime 保存渗透黑板并调度 Pi Worker；独立 SecMind 服务处理代码审计、逆向及日志分析。目标和样本必须处于授权范围内。

## 快速开始

在本 README 所在目录打开 PowerShell。首次初始化会创建缺失的 `.env`；没有 `an/.env` 的模型密钥时，脚本完成其他检查后会以失败码结束。填写 `an/.env` 和 `secmind/.env` 后重跑，并先启动工作台与统一 API：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-all.ps1
# 按第 3.1 节核对密钥、模型地址及 SecMind 启动脚本
powershell -ExecutionPolicy Bypass -File .\setup-all.ps1
powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -Only an-api,frontend
```

打开 `http://127.0.0.1:5173/models`，在“模型与用量”保存共享模型服务地址、密钥和模型 ID，生成 `an/data/model-runtime.json`；同时检查 `security-runtime/dispatch.pi.local.yaml` 中的本机 Pi 路径。然后启动其余组件：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-all.ps1
```

以后已有有效共享模型配置时，可直接运行 `start-all.ps1`。工作台入口是 `http://127.0.0.1:5173`；停止服务使用 `powershell -ExecutionPolicy Bypass -File .\stop-all.ps1`。完整在线任务还需要模型服务、Pi CLI、目标网络和相应工具可用；仅看到首页不代表任务链路已通过。

## 1. 程序结构

```text
套件根目录
├─ an/                         统一平台后端（FastAPI）
│  ├─ src/security_agent/      调度、任务、模型、记忆、报告和模块集成
│  ├─ frontend/                React + Ant Design + Vite 工作台
│  ├─ data/                    SQLite、上传文件和运行数据
│  └─ .env                     统一平台配置与模型密钥
├─ secmind/                    逆向/代码/证据审计服务（FastAPI）
│  ├─ src/secmind/             API、编排、工具、安全闸和模型网关
│  ├─ tests/                   单元、集成和平台相关测试
│  └─ .env                     SecMind 配置与模型密钥
├─ security-runtime/           渗透协作运行时
│  ├─ security-runtime/        Python 服务端与 Dispatcher 实现
│  ├─ container/               Kali/CTF 工具容器定义
│  ├─ datas/                   Runtime SQLite 数据
│  ├─ dispatch.pi.local.yaml   Pi 调度、模型共享和本机路径
│  └─ dispatch.local.yaml      本机 Claude Worker 回退配置
├─ _runtime/                   进程状态、日志、内部回调凭据（自动生成）
├─ setup-all.ps1/.cmd          初始化入口
├─ start-all.ps1/.cmd          一键启动入口
└─ stop-all.ps1/.cmd           一键关闭入口
```

调用关系：浏览器访问 5173，Vite 将 `/api` 与 `/health` 代理到 8001。统一平台在在线任务中与 8000 的黑板、8002 的分析服务通信；Runtime 的 Dispatcher 领取项目后调用本机 Pi CLI，Pi 经工作台黑板桥接调用已授权工具。默认启动脚本将服务绑定到 `127.0.0.1`。

当前部署范围为本机单用户。三个 API 默认仅接受 `127.0.0.1`、`localhost` 的 Host；浏览器写操作和 WebSocket 拒绝未授权来源，命令行与服务间调用可以不携带 Origin。前端使用 `http://127.0.0.1:5173`。如显式配置反向代理，可分别设置 `SECURITY_AGENT_ALLOWED_HOSTS` / `SECURITY_AGENT_ALLOWED_BROWSER_ORIGINS`、`SECMIND_ALLOWED_HOSTS` / `SECMIND_ALLOWED_BROWSER_ORIGINS`、`SECURITY_RUNTIME_ALLOWED_HOSTS` / `SECURITY_RUNTIME_ALLOWED_BROWSER_ORIGINS`，值为逗号分隔的精确主机名或完整来源（含协议和端口）；不要将可信 Host 配为 `*`。Docker Compose 单独允许对应内部服务名。来源校验不代替多用户登录鉴权。

| 组件 | 端口 | 作用 | 必需性 |
|---|---:|---|---|
| React/Vite 前端 | 5173 | 用户界面 | 正常交互时需要 |
| Security Runtime | 8000 | 项目、黑板、意图、依赖和 Worker 租约 | 在线协作任务需要 |
| 统一平台 API | 8001 | 总入口、任务编排、WebSocket、报告 | 必需 |
| SecMind API | 8002 | 代码审计、逆向和日志分析 | 对应模块需要 |
| Dispatcher | 无监听端口 | 从 8000 取任务并启动 Pi Worker | 自动渗透任务需要 |

## 2. 初始环境

推荐系统为 64 位 Windows 10/11，使用 Windows PowerShell 5.1 或 PowerShell 7。路径可以包含中文或空格，但应保留当前目录结构。

必须安装：

- `uv`：管理 Python 和虚拟环境。
- Python 3.13：`an`、`secmind` 要求 `>=3.11,<3.14`，Runtime 要求 `>=3.12`；初始化脚本会由 uv 准备 3.13。
- Node.js：前端需要。Vite 7 建议 Node `>=20.19` 或 `>=22.12`。
- 可访问 Python/npm 依赖源的网络（首次初始化需要）。

按功能选装：

- Pi CLI：默认 Dispatcher 需要；初始化脚本缺少 Pi 时会尝试通过 npm 全局安装。Claude Code CLI 只用于回退配置。
- Docker Desktop：Kali 容器或 SecMind 沙箱等容器执行需要；四个本地 Web 服务和内置桌面 MCP 工具不依赖 Docker。
- PostgreSQL/Qdrant：本机套件默认可用 SQLite 启动；SecMind 的完整集成测试、独立 Compose 部署和可选向量检索按各自配置准备服务。

安装示例：

```powershell
winget install --id Astral-sh.uv -e
winget install --id OpenJS.NodeJS.LTS -e
npm install -g @mariozechner/pi-coding-agent
```

安装后重新打开 PowerShell，并检查：

```powershell
uv --version
node --version
npm --version
pi --version           # 不使用 Dispatcher 时可忽略
docker version         # 不使用容器工具时可忽略
```

## 3. 首次初始化

在本 README 所在的套件根目录打开 PowerShell；以下相对路径命令均从该目录执行。

执行一键初始化：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-all.ps1
```

也可以双击 `setup-all.cmd`。初始化脚本会：

1. 检查 `an`、`secmind`、`security-runtime` 目录。
2. 检查或安装 uv，并由 uv 准备 Python 3.13。
3. 检查 Node/npm 和默认的 Pi CLI；保留可选的 Claude CLI 检查。
4. 从 `.env.example` 生成缺失的 `.env`。
5. 同步三个 Python 项目的虚拟环境。
6. 在 `an/frontend` 安装 npm 依赖。

脚本会为 `an`、`secmind` 复制配置模板，并生成兼容旧配置的 `security-runtime/.env`。没有 `an/.env` 中的 `SECURITY_AGENT_MODEL_API_KEY` 时，它仍会报告失败；填写后重跑即可。脚本可能把该密钥写入 SecMind 的空白 DeepSeek/Qwen 字段和 Runtime 的 Claude 字段，不能据此认定三个服务都使用同一服务商或同一接口协议。

若只想检查配置、暂不重建环境：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-all.ps1 -SkipVenv -SkipFrontend
```

### 3.1 模型与密钥

启动前至少检查以下文件，不要把真实密钥提交到版本库或发送给无关人员：

- `an/.env`：检查 `SECURITY_AGENT_MODEL_BASE_URL`、`SECURITY_AGENT_MODEL_API_KEY`、模型 ID、`SECURITY_AGENT_REVERSE_BASE_URL` 和 `SECURITY_AGENT_PENETRATION_BASE_URL`。模板中 `SECURITY_AGENT_DEMO_MODE=true`；仅填写密钥不会自动切到在线模式。
- 工作台“模型与用量”页面保存配置到 `an/data/model-runtime.json`，并根据密钥切换演示模式；API 重启时该文件优先于 `.env` 中的模型地址、密钥和模型 ID。默认 Pi Dispatcher 也读取此文件，新一轮调度才使用更新后的配置。文件含真实密钥，应按密钥文件保护。
- `secmind/.env`：独立配置模型、可信 URL 和凭据，不读取上述共享文件。本套件的 `secmind/启动在线.ps1` 还会将模型模式设为 live，并覆盖 `.env` 中的可信模型 URL 与 Qwen URL；使用其他网关前应核对该启动脚本。此本机入口还启用了仅供开发使用的工具回退，不能按生产沙箱部署理解。
- `security-runtime/dispatch.pi.local.yaml`：确认 Runtime/工作台地址、并发数和 `workers[].env.PI_CLI_JS`。当前文件的 `PI_CLI_JS` 是机器绝对路径，迁移目录或电脑后须改为实际 Pi 包的 `dist/cli.js`；启动脚本自动探测的路径不能覆盖 YAML 中的固定值。Claude 回退配置是 `dispatch.local.yaml`。
- `security-runtime/.env`：初始化脚本保留的旧式 `ANTHROPIC_*` 配置；当前 Pi 和 Claude Dispatcher 启动脚本都读取共享模型文件，不直接加载它。独立 Pi 模式另用 `.env.pi` 和 `dispatch.pi.independent.yaml`。当 SecMind 启用 operator token 时，在 `an/.env` 设置 `SECURITY_AGENT_SECMIND_OPERATOR_TOKEN`，不要复用模型 API Key。

对外交付前检查 `an/.env`、`secmind/.env`、`security-runtime/.env`、`an/data/model-runtime.json` 和 `_runtime/planning-callback.token`，移除或轮换交付者凭据。默认本机安全边界是单用户和回环监听，没有多用户登录鉴权。

Windows 上使用默认 Dispatcher 时，先确认 Pi CLI 可执行；使用 Claude 回退入口时，另确认 `claude.exe`：

```powershell
(Get-Command pi).Source
pi --help
```

## 4. 启动程序

推荐一键启动：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-all.ps1
```

不运行自动渗透 Dispatcher：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -SkipDispatcher
```

脚本按 8000、Dispatcher、8002、8001、5173 的顺序启动，后台隐藏运行。进程状态写入 `_runtime/services.json`，带时间戳的日志写入 `_runtime/logs`。仅复用经过目录与命令核验的本套件进程；其他程序占用端口时会报错。Dispatcher 按配置文件持有系统级独占锁，重复启动不会生成第二个调度器。

使用 `powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -Only an-api,dispatcher` 可以只启动指定组件；重复执行会复用现有进程。SecMind 使用 `/health/ready` 检查就绪状态。`-SkipDispatcher` 只跳过自动 Worker，不跳过 Runtime API；需要最小工作台时可用 `-Only an-api,frontend`，但依赖 8000/8002 的任务模块不会完整工作。

### 4.1 默认 Pi Worker 配置

`start-all.ps1` 和 `security-runtime/start-runtime-dispatcher.ps1` 默认启动本机 Pi Worker。工作台“模型与用量”页面保存共享服务地址、密钥、规划模型和工作模型；Dispatcher 每轮派发前重新读取，已经启动的 Worker 仍使用原配置。SecMind 分析服务的模型配置独立。跨轮规划的运行链路、预算和旧任务兼容边界见 [持续规划说明](docs/continuous-workbench-planning.md) 与 [步骤依赖操作说明](docs/artex-planning-operations.md)。

```powershell
powershell -ExecutionPolicy Bypass -File .\security-runtime\start-runtime-dispatcher-pi.ps1
```

Pi 默认配置位于 `security-runtime/dispatch.pi.local.yaml`，使用本机 Pi CLI，不依赖 Worker 容器镜像。若要独立于页面配置 Pi 服务商，复制 `security-runtime/.env.pi.example` 为 `.env.pi`，填写全部 `PI_*` 参数，再运行 `start-runtime-dispatcher-pi.ps1 -Independent`；对应 YAML 为 `dispatch.pi.independent.yaml`，此模式不跟随页面更新。Pi 的可执行安全工具经工作台黑板校验，本地内置工具仅开放读取。Claude 回退入口是 `security-runtime/start-runtime-dispatcher-claude.ps1`；两个 Dispatcher 不能同时运行。

Docker Compose 的旧 Claude Dispatcher 已移入 `claude-dispatcher` profile；普通 `docker compose up` 不会再启动它。需要旧容器模式时必须显式启用该 profile，并先停止本机 Pi Dispatcher。

启动完成后访问：

- 前端：`http://127.0.0.1:5173`
- 统一 API 文档：`http://127.0.0.1:8001/docs`
- Runtime API 文档：`http://127.0.0.1:8000/docs`
- SecMind API 文档：`http://127.0.0.1:8002/docs`

手工分终端启动（用于排错）：

```powershell
# 终端 1
.\security-runtime\start-runtime-server.ps1

# 终端 2，可选
.\security-runtime\start-runtime-dispatcher.ps1

# 终端 3
.\secmind\启动在线.ps1

# 终端 4
.\an\启动在线.ps1

# 终端 5
.\an\frontend\启动前端.ps1
```

### 4.2 功能入口与边界

| 入口 | 当前行为与说明 |
|---|---|
| `/cockpit`、`/audit` | 查看持久任务指标与主机快照、审计事件和账本回放；报告结论需回看对应证据 |
| `/workbench` | 创建/重试任务，查看执行画布、黑板、证据与报告；在线任务使用跨轮规划、步骤依赖和独立目标核验，见 [持续规划](docs/continuous-workbench-planning.md) 与 [步骤依赖](docs/artex-planning-operations.md) |
| 任务详情的旁路问答 | 基于已保存的模型请求快照单独提问，独立计费与取消，不修改主任务；见 [操作说明](docs/artex-side-question-operations.md) |
| 任务结果的独立复核 | 新建带独立预算的子任务，复核发现或应急处置记录；不会改写原报告，见 [复核边界](docs/artex-retest-operations.md) |
| `/assets` | 从现有任务和回执汇总跨任务资产及观测来源，不主动探测；见 [资产库](docs/asset-library-operations.md) |
| 任务黑板的冷节点摘要 | 可查看折叠投影及原始节点；模型摘要和长任务节省对照尚未完成，见 [操作说明](docs/artex-cold-digest-operations.md) |
| `/incident-response` | 本地主机采集及受审批的处置操作，均作用于当前机器；参见 [统一平台说明](an/README.md) |
| `/experiences`、`/prompts` | 管理经验条目与 Prompt 模板；模型调用和经验引用保留任务记录 |
| `/models`、`/mcp` | 管理共享模型配置与 MCP 连接、工具发现和调用回执；SecMind 模型独立配置，MCP 接入步骤见下文 |

任务归档与隔离恢复仍在分阶段实现，目前不能作为完整备份/恢复入口使用；当前已实现范围和剩余工作见 [ARTEX 执行计划](docs/artex-execution-plan.md)。TSec 在线评测是可选集成：自动启动容器、建任务、提交 flag 使用 `tsec-auto.cmd`，手动批量工具为 `TSec批量工具.cmd` / `tsec-batch.cmd`，配置及边界见 [TSec 接入说明](docs/tsec-benchmark.md)。

### 4.3 MCP 工具接入

1. 首次运行 `powershell -ExecutionPolicy Bypass -File .\setup-security-tools.ps1`。脚本准备/校验 Burp 文件、检查 Yakit/Yak、TscanPlus、Reqable，并在 `an/data/mcp-catalog.json` 注册四个本机连接；搬迁目录后重跑可修复可执行文件路径，保留已有启用状态。Burp 需要本机 Java，首次准备可能访问下载源。
2. 运行 `powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -StartSecurityTools`，或双击 `start-with-security-tools.cmd`。它们会启动套件、Reqable 和 Burp；Yakit/Yak、TscanPlus 由 MCP 连接按需以 stdio 启动。已启动套件时也可单独运行 `.\start-security-tools.ps1`。
3. Burp Community 首次打开时完成项目向导，在扩展的 MCP 设置中启用监听 `127.0.0.1:9876`；注册使用 SSE 根地址 `http://127.0.0.1:9876`。Reqable 桌面程序需保持运行，其 MCP Server 使用本机 `9001` 端口。具体界面操作见 [内置安全工具说明](SECURITY_TOOLS.md)。
4. 打开 `http://127.0.0.1:5173/mcp`，对已启用的 Server 点击“连接并发现工具”，查看握手状态、发现的工具和最近回执。握手成功只说明当时连接可用，不表示任务已经调用该工具。少数已审查的 Base64/JWT 等纯转换工具可在此页输入 JSON 参数并直接调用；其他工具必须从任务工作台发起，管理接口也会拒绝绕过任务的直接调用。
5. 在线任务会在规划时选用已启用且已发现的 MCP 工具；Pi Worker 经工作台黑板桥接调用，调用与任务、项目、意图、attempt、授权范围和预算绑定。需要审批时在任务详情处理；请求 ID、工具版本及参数绑定回执，服务中断后的未知结果不会自动重放非幂等操作。工具成功仅表示调用完成，漏洞和任务目标仍需单独核验证据。

本机 `secmind-local` 是内置 MCP；Kali 连接需另行启用容器能力。模型未配置或仍处于 DEMO 时，不应把 MCP 页面发现成功理解为 Agent 会自动使用这些工具。连接失败先核对桌面程序、端口、`an/data/mcp-catalog.json` 中的实际路径与 `_runtime/logs`；TscanPlus 签名校验失败会拒绝连接。停止套件不会关闭桌面程序，另用 `.\stop-security-tools.ps1` 请求关闭。

## 5. 启动后检查

```powershell
$urls = @(
  'http://127.0.0.1:5173/',
  'http://127.0.0.1:8000/projects',
  'http://127.0.0.1:8001/health',
  'http://127.0.0.1:8002/health/ready'
)
$urls | ForEach-Object {
  $response = Invoke-WebRequest $_ -UseBasicParsing -TimeoutSec 5
  "$_ -> HTTP $($response.StatusCode)"
}
```

全部启动时四项均应返回 200；若用了 `-Only`，只检查实际启动的组件。健康探针仅确认 HTTP 服务可响应。要验证模型账户、Pi 调度、模块调用、审批和 WebSocket 事件，应在前端提交无敏感数据且处于授权范围的最小任务，并核对其终态与报告；在线测试可能产生费用。

查看日志：

```powershell
Get-ChildItem .\_runtime\logs\*.err.log | Sort-Object LastWriteTime -Descending | Select-Object -First 5
# 用上一步显示的实际文件名读取日志
Get-ChildItem .\_runtime\logs\an-api-*.err.log | Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 | Get-Content -Tail 100
```

开发验证命令：

```powershell
# 前端
Set-Location .\an\frontend
npm test
npm run build

# Python；在各项目目录运行，可选依赖必须显式启用
Set-Location ..
uv run --extra dev --extra qdrant pytest -q
Set-Location ..\secmind
uv run --extra dev --extra full pytest -q
Set-Location ..\security-runtime\security-runtime
uv run pytest -q
```

完整回归可能需要隔离测试 `.env`、PostgreSQL、Qdrant、评测素材及 Windows 不提供的 POSIX/符号链接能力；不要在生产数据目录上运行依赖外部服务的测试。近期各功能的固定夹具与测试边界见上表所链接的操作文档；2026-10-11/12 的本机上线验收记录见 [上线验收清单](docs/release-acceptance-2026-10-11.md)，它不是当前环境的实时验收结论。

## 6. 关闭程序

正常关闭：

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-all.ps1
```

也可以双击 `stop-all.cmd`。脚本重新检查进程所属目录、命令与创建时间，仅结束本套件的进程树；不会根据端口或旧 PID 文件终止其他程序，数据和日志保留。可先执行 `.\stop-all.ps1 -Only an-api,dispatcher -WhatIf` 演练，再去掉 `-WhatIf` 执行。通过 `start-with-security-tools.cmd` 启动的桌面工具另用 `.\stop-security-tools.ps1` 正常关闭。

检查当前端口：

```powershell
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 5173,8000,8001,8002 |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

关闭后确认：

```powershell
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object LocalPort -in 5173,8000,8001,8002
```

没有输出即表示四个监听端口已释放。手工前台启动的进程可在各自终端按 `Ctrl+C` 关闭。

## 7. 常见故障

- `uv` 找不到：重开终端，确认 uv 安装目录在用户 `PATH`，或重新运行初始化脚本。
- `ModuleNotFoundError`：先运行 `setup-all.ps1`；运行测试时使用上文带 `--extra` 的命令。
- 5173 启动失败：确认 Node 版本满足 Vite 7 要求，在 `an\frontend` 执行 `npm ci`。
- Dispatcher 找不到/卡在 Pi：确认 `Get-Command pi` 可用、`pi --help` 可运行，检查 `dispatch.pi.local.yaml` 中 `PI_CLI_JS` 的实际文件位置和 `an/data/model-runtime.json` 的共享模型配置；独立模式再检查 `.env.pi`。使用 Claude 回退入口时，再检查 `claude` 和 `dispatch.local.yaml`。
- 服务健康但任务失败：依次检查 8001、8002、8000 和 Dispatcher 日志，重点确认模型名、Base URL、密钥权限、余额与网络代理。
- 端口被占用：先查明 `OwningProcess`；不要直接运行关闭脚本杀掉不相关服务。
- Docker 工具失败：确认 Docker Desktop 已启动、Linux 容器可用，当前用户有访问 Docker 引擎的权限。
- 模型密钥已填写但仍显示 DEMO：检查 `an/.env` 的 `SECURITY_AGENT_DEMO_MODE`，以及是否存在覆盖 `.env` 的 `an/data/model-runtime.json`；通过工作台保存模型配置后再看 `/health` 的 `demo_mode`。
- SecMind 模型连通失败：检查其独立密钥、可信 URL，以及 `secmind/启动在线.ps1` 对 live 模式和 URL 的覆盖；8002 就绪不代表上游模型可用。
- Windows 测试出现 POSIX/symlink/Git/PostgreSQL 失败：在带 Git 元数据的 Linux/WSL CI 中配置外部服务后执行完整发布测试。

## 8. 数据与安全

- `an/data`、`secmind/data` 及 `security-runtime/datas` 可能包含任务、报告、上传样本和数据库。
- `_runtime\logs` 可能包含目标地址、错误上下文或模型输出；对外提供前先审查。
- `an\data\uploads` 可能含可执行文件或恶意样本。不要双击，扫描、复制和清理时按不可信文件处理。
- `.env`、`an/data/model-runtime.json` 和 `_runtime/planning-callback.token` 含凭据，不应进入公开压缩包、截图或工单。
- 服务默认仅绑定本机回环地址。若要改为局域网监听，必须先增加身份认证、访问控制、防火墙和 TLS。
- 关闭服务不会删除数据库、上传文件或日志；需要清理数据时先备份并确认精确目录，不能把整个套件根目录作为递归删除目标。
