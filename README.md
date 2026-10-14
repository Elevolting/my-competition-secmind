# Security Agent Suite 使用与运维说明

TSec 在线评测接口已接入统一平台，配置及调用方式见 [TSec Challenges API 接入](docs/tsec-benchmark.md)。
自动闭环（启动容器、创建本地解题任务、提取并提交 flag）用 `tsec-auto.cmd`；手动批量启动和提交请双击 `TSec批量工具.cmd`，命令行入口为 `tsec-batch.cmd`。

本文档适用于当前 Windows 交付目录。该套件把统一 Web 平台、渗透任务运行时和逆向/安全分析服务组合为一个本地系统。

已内置 Burp、Yakit/Yak、TscanPlus、Reqable 的 MCP。双击 `start-with-security-tools.cmd` 启动，配置和验证结果见 [内置安全工具说明](SECURITY_TOOLS.md)。

2026-10-01 已补齐任务恢复、预算执行、外部审批、SecMind 代码审计/日志分析接入和可信报告刷新。当前实现、验收结果及尚未配置的能力见 [完善与验收记录](docs/completion-2026-10-01.md)。

## 1. 程序结构

```text
套件根目录
├─ an/                         统一平台后端（FastAPI）
│  ├─ src/security_agent/      调度、任务、模型、记忆、报告和模块集成
│  ├─ frontend/                React + Ant Design + Vite 前端
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
│  ├─ dispatch.pi.local.yaml   默认本机 Pi Worker 调度配置
│  ├─ dispatch.local.yaml      保留的 Claude Worker 调度配置
│  └─ .env                     Claude 兼容接口配置
├─ _runtime/                   PID 和运行日志（自动生成）
├─ setup-all.ps1/.cmd          初始化入口
├─ start-all.ps1/.cmd          一键启动入口
└─ stop-all.ps1/.cmd           一键关闭入口
```

调用关系：浏览器访问 5173；前端调用 8001；8001 根据任务类型调用 8000（渗透）或 8002（逆向/审计）；Dispatcher 轮询 8000 的项目并调用本机 Pi CLI Worker。默认所有服务只监听 `127.0.0.1`。

当前部署范围为本机单用户。三个 API 默认仅接受 `127.0.0.1`、`localhost` 的 Host；浏览器写操作和 WebSocket 拒绝未授权来源，命令行与服务间调用可以不携带 Origin。前端使用 `http://127.0.0.1:5173`。如显式配置反向代理，可分别设置 `SECURITY_AGENT_ALLOWED_HOSTS` / `SECURITY_AGENT_ALLOWED_BROWSER_ORIGINS`、`SECMIND_ALLOWED_HOSTS` / `SECMIND_ALLOWED_BROWSER_ORIGINS`、`SECURITY_RUNTIME_ALLOWED_HOSTS` / `SECURITY_RUNTIME_ALLOWED_BROWSER_ORIGINS`，值为逗号分隔的精确主机名或完整来源（含协议和端口）；不要将可信 Host 配为 `*`。Docker Compose 单独允许对应内部服务名。来源校验不代替多用户登录鉴权。

| 组件 | 端口 | 作用 | 必需性 |
|---|---:|---|---|
| React/Vite 前端 | 5173 | 用户界面 | 正常交互时需要 |
| Security Runtime | 8000 | 统一任务黑板、项目和意图；渗透任务另由 Dispatcher 执行 Worker | 非演示模式需要 |
| 统一平台 API | 8001 | 总入口、任务编排、WebSocket、报告 | 必需 |
| SecMind API | 8002 | 逆向、代码和安全审计 | 对应任务需要 |
| Dispatcher | 无监听端口 | 从 8000 取任务并启动 Pi Worker | 自动渗透任务需要 |

## 2. 初始环境

推荐系统为 64 位 Windows 10/11，使用 Windows PowerShell 5.1 或 PowerShell 7。路径可以包含中文或空格，但应保留当前目录结构。

必须安装：

- `uv`：管理 Python 和虚拟环境。
- Python 3.13：`an` 和 `secmind` 要求 `>=3.11,<3.14`，初始化脚本会由 uv 安装 3.13。
- Node.js：前端需要。Vite 7 建议 Node `>=20.19` 或 `>=22.12`。
- 可访问 Python/npm 依赖源的网络（首次初始化需要）。

按功能选装：

- Pi CLI：默认自动渗透 Dispatcher 需要；Claude Code CLI 仅在使用回退配置时需要。
- Docker Desktop：仅容器化安全工具、沙箱或 Kali 任务需要；启动四个本地 Web 服务不需要。
- PostgreSQL/Qdrant：默认本地 SQLite/内存路径可以启动；生产持久化、集成测试或向量检索按配置另行部署。

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

进入套件根目录：

```powershell
Set-Location -LiteralPath 'D:\tzb\SecMind\security-agent-suite-clean-20260904(2)'
```

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

若只想检查配置、暂不重建环境：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-all.ps1 -SkipVenv -SkipFrontend
```

### 3.1 配置文件

启动前至少检查以下文件，不要把真实密钥提交到版本库或发送给无关人员：

- `an\.env`：确认 `SECURITY_AGENT_MODEL_BASE_URL`、`SECURITY_AGENT_MODEL_API_KEY`、模型名、8000/8002 模块地址。
- `secmind\.env`：确认 `SECMIND_DEEPSEEK_API_KEY`/`SECMIND_QWEN_API_KEY`、可信模型 URL 和模型名。
- `security-runtime\.env`：仅在使用 Claude 回退入口时确认 `ANTHROPIC_MODEL`、`ANTHROPIC_BASE_URL`、`ANTHROPIC_AUTH_TOKEN`。
- `security-runtime\dispatch.pi.local.yaml`：确认 Runtime 地址和并发数符合目标机器资源；Claude 回退配置为 `dispatch.local.yaml`。

当前初始化脚本可能把 `an` 的模型密钥复制到另外两处空白密钥字段。分发程序前必须轮换或移除交付者的真实密钥。

Windows 上使用默认 Dispatcher 时，先确认 Pi CLI 可执行；使用 Claude 回退入口时，再确认 `claude.exe`：

```powershell
(Get-Command pi).Source
pi --help
```

## 4. 启动程序

推荐一键启动：

```powershell
Set-Location -LiteralPath 'D:\tzb\SecMind\security-agent-suite-clean-20260904(2)'
powershell -ExecutionPolicy Bypass -File .\start-all.ps1
```

不运行自动渗透 Dispatcher：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -SkipDispatcher
```

脚本按 8000、Dispatcher、8002、8001、5173 的顺序启动，后台隐藏运行。进程状态写入 `_runtime\services.json`，带时间戳的日志写入 `_runtime\logs`。仅复用经过目录与命令核验的本套件进程；其他程序占用端口时会报错。Dispatcher 按配置文件持有系统级独占锁，重复启动不会生成第二个调度器。

使用 `./start-all.ps1 -Only an-api,dispatcher` 可以只启动指定组件；重复执行会复用现有进程。SecMind 使用 `/health/ready` 检查可执行状态。

### 默认 Pi Worker 配置

`start-all.ps1` 和 `security-runtime\start-runtime-dispatcher.ps1` 默认启动本机 Pi Worker。模型配置页统一管理服务地址、密钥、规划模型和工作模型：规划模型供主任务及 Pi 意图规划使用，工作模型供主任务及 Pi 的 Bootstrap、Explore 使用。保存后，Pi 从下一轮调度读取新配置，已启动的任务继续使用旧配置。Pi 与 Claude 的 Dispatcher YAML 仍独立；Claude 回退配置在 `security-runtime\dispatch.local.yaml`。

```powershell
powershell -ExecutionPolicy Bypass -File .\security-runtime\start-runtime-dispatcher-pi.ps1
```

Pi 默认配置位于 `security-runtime\dispatch.pi.local.yaml`，使用本机 `pi` 命令，不依赖 Worker 容器镜像。若确实要让 Pi 使用独立于页面的服务商配置，复制 `security-runtime\.env.pi.example` 为 `.env.pi`，填写全部 `PI_*` 参数，运行 `start-runtime-dispatcher-pi.ps1 -Independent`；对应 YAML 为 `dispatch.pi.independent.yaml`，此模式不跟随页面更新。Pi 的可执行安全工具经工作台黑板校验；本地内置工具仅开放读取。原 Claude 配置可通过 `security-runtime\start-runtime-dispatcher-claude.ps1` 启动；两个 Dispatcher 不能同时运行。

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

四项均应返回 200。再在前端提交一个**无敏感数据、已授权**的最小测试任务，才能验证模型账户、模块调用和 WebSocket 事件链路。在线测试可能产生费用。

查看日志：

```powershell
Get-ChildItem .\_runtime\logs\*.err.log | Sort-Object LastWriteTime -Descending | Select-Object -First 5
# 用上一步显示的实际文件名读取日志
Get-ChildItem .\_runtime\logs\an-api-*.err.log | Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 | Get-Content -Tail 100
```

开发验证命令：

```powershell
# 前端（当前已验证通过）
Set-Location .\an\frontend
npm test
npm run build

# Python；可选依赖必须显式启用
Set-Location ..
uv run --extra dev --extra qdrant pytest -q
Set-Location ..\secmind
uv run --extra dev --extra full pytest -q
Set-Location ..\security-runtime\security-runtime
uv run pytest -q
```

注意：完整 Python 测试需要隔离测试 `.env`，并可能需要 Linux/POSIX、PostgreSQL、Qdrant、Git 元数据、符号链接权限及评测素材。在当前 Windows 运行目录直接执行时，不能期待全绿。

## 6. 关闭程序

正常关闭：

```powershell
Set-Location -LiteralPath 'C:\kaifa\security-agent-suite-clean-20260904(3)'
powershell -ExecutionPolicy Bypass -File .\stop-all.ps1
```

也可以双击 `stop-all.cmd`。脚本重新检查进程所属目录、命令与创建时间，仅结束本套件的进程树；不会根据端口或旧 PID 文件终止其他程序，数据和日志保留。可先执行 `./stop-all.ps1 -Only an-api,dispatcher -WhatIf` 演练，再去掉 `-WhatIf` 执行。

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
- Dispatcher 找不到/卡在 Pi：确认 `Get-Command pi` 可用、`pi --help` 可运行，并检查 `dispatch.pi.local.yaml` 及可选的 `.env.pi`。使用 Claude 回退入口时，再检查 `claude` 和 `dispatch.local.yaml`。
- 服务健康但任务失败：依次检查 8001、8002、8000 和 Dispatcher 日志，重点确认模型名、Base URL、密钥权限、余额与网络代理。
- 端口被占用：先查明 `OwningProcess`；不要直接运行关闭脚本杀掉不相关服务。
- Docker 工具失败：确认 Docker Desktop 已启动、Linux 容器可用，当前用户有访问 Docker 引擎的权限。
- Windows 测试出现 POSIX/symlink/Git/PostgreSQL 失败：在带 Git 元数据的 Linux/WSL CI 中配置外部服务后执行完整发布测试。

## 8. 数据与安全

- `an\data`、`secmind` 的运行目录及 `security-runtime\datas` 可能包含任务、报告、上传样本和数据库。
- `_runtime\logs` 可能包含目标地址、错误上下文或模型输出；对外提供前先审查。
- `an\data\uploads` 可能含可执行文件或恶意样本。不要双击，扫描、复制和清理时按不可信文件处理。
- `.env` 含密钥，不应进入公开压缩包、截图或工单。
- 服务默认仅绑定本机回环地址。若要改为局域网监听，必须先增加身份认证、访问控制、防火墙和 TLS。
- 关闭服务不会删除数据库、上传文件或日志；需要清理数据时先备份并确认精确目录，不能把整个套件根目录作为递归删除目标。
